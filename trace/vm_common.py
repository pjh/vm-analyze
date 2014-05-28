# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

IGNORE_SHARED_LIBS = True
IGNORE_SHARED_FILES = True
IGNORE_GUARD_REGIONS = True

from util.pjh_utils import *
from trace.vm_regex import *
import conf.system_conf as sysconf
import re

PAGE_SIZE_4KB = 4 * KB_BYTES
PAGE_SIZE_2MB = 2 * MB_BYTES
PAGE_SIZE_1GB = GB_BYTES

PAGE_SIZE_KB          =      4
PAGE_SIZE_BYTES       =   4096
MAX_ADDR64 = int(0xffffffffffffffff)

PERMS = ["---p", "r--p", "r--s", "rw-p", "rw-s", "rwxp", 'rwxs', "r-xp", 'r-xs']
	# vmware-vmx actually maps a couple of files (/etc/passwd,
	# /usr/lib/vmware/icu/icudt44l.dat) as r-xsf - bizarre...
	# It also has some rwxsf mappings, which make a little more sense,
	# but still, why would you want these to be executable? The files
	# are: /tmp/vmware-pjh/ram111; /dev/vmmon; /vmem.
	#   /tmp/vmware-pjh/ram111 and /vmem appear to be SYS-V shared
	#   memory; /dev/vmmon is some kind of weird device file...
MAP_TYPES = ["f", "a"]  # file-backed, anonymous
PERMS_KEYS = list()
for perms in PERMS:
	for map_type in MAP_TYPES:
		PERMS_KEYS.append("{0}{1}".format(perms, map_type))
MEM_TYPES = ["Size", "Rss", "Pss", "Shared_Clean", "Shared_Dirty",
	"Private_Clean", "Private_Dirty", "Referenced", "Anonymous",
	"AnonHugePages", "Swap", "KernelPageSize", "MMUPageSize", 
	"Locked"]  # all of the different memory types in the smaps files.

# This is an "enum" for the different types of operations that can be
# performed on a vma. These should correspond to the types of mmap_vma_*
# kernel trace events that I've added.
VMA_OP_TYPES = [
	'alloc',
	'free',
	'resize',
	'relocation',
	'access_change',
	'flag_change'
	]
# Segment ops is a subset of VMA_OP_TYPES: these are the operations
# that we "care about" for implementing segments, i.e. operations that
# will require some work to be done in *physical* memory.
SEGMENT_OPS = [
	'alloc',
	'resize',
	]

def is_multiple_of_page_size(bytes_):
	if bytes_ % PAGE_SIZE_BYTES == 0:
		return True
	return False

def next_multiple_of_page_size(bytes_):
	while bytes_ % PAGE_SIZE_BYTES != 0:
		bytes_ += 1
	return bytes_

# Returns true if the name of this mapping is one of the "special" mappings
# in the smaps file: [heap], [stack], [vdso], or [vsyscall].
def is_special_mapping(filename):
	if (filename == "[stack]" or filename == "[vdso]" or
		filename == "[vsyscall]" or filename == "[heap]"):
		return True
	return False

# Returns true if the name of this mapping is one of the "special" mappings
# that appear near the end of the smaps file: [stack], [vdso], or [vsyscall].
def is_special_end_mapping(filename):
	if (filename == "[stack]" or filename == "[vdso]" or
		filename == "[vsyscall]"):
		return True
	return False

'''
Make sure that filename is a stripped string and inode is an int!
'''
def is_mapping_anonymous(inode, filename):
	# At the moment, the [heap] (if present), [stack], [vdso], and [vsyscall]
	# mappings will count as anonymous, not file-backed!
	#   They should really be their own separate memory types...
	if inode == 0:
		if (not filename or is_special_mapping(filename)):
			return True
	return False

def is_mapping_below_stack(filename):
	if not filename:
		return True
	if (filename == "[stack]" or filename == "[vdso]" or
		filename == "[vsyscall]"):
		return False
	return True

'''
Constructs a dictionary key based on an smaps entry's permissions and its
file name / inode, which are used to determine if the mapping is file-backed
or anonymous. This function can be called immediately after performing the
regular expression to match an smaps header line.
'''
def construct_perms_key(perms, inode, filename):
	tag = 'construct_perms_key'

	# If inode is equal to 0, then this mapping corresponds to either
	# [heap], [stack], [vdso], or an anonymous mapping (i.e. mmap).
	# Be sure to strip the filename string of any trailing whitespace:
	inode = int(inode)
	filename = (str(filename)).strip()
	anonymous = is_mapping_anonymous(inode, filename)
	if anonymous:
		key = "{0}{1}".format(perms, "a")  # must match PERMS_KEYS!!
	else:
		key = "{0}{1}".format(perms, "f")

	if key not in PERMS_KEYS:
		print_error_exit(tag, ("whoa: constructed key={0} not in "
			"PERMS_KEYS={1}").format(key, PERMS_KEYS))

	return key

# prot is the "prot" argument to an mmap() or mprotect() syscall,
# as shown in strace output; e.g., PROT_READ or PROT_READ|PROT_WRITE.
# Returns: a tuple of booleans: (prot_r, prot_w, prot_x)
def extract_prot_bools(prot):
	tag = 'extract_prot_bools'

	prot_r = False
	prot_w = False
	prot_x = False
	prot_none = False
	if "PROT_READ" in prot:
		prot_r = True
	if "PROT_WRITE" in prot:
		prot_w = True
	if "PROT_EXEC" in prot:
		prot_x = True
	if "PROT_NONE" in prot:
		if prot_r or prot_w or prot_x:
			print_error_exit(tag, ("got PROT_NONE with some other prot "
			    "flag! - {0}").format(prot))
		prot_none = True
	if not (prot_r or prot_w or prot_x) and not prot_none:
		print_warning(tag, ("hmmmm, no other prot set, so prot_none by "
		    "default: {0}").format(prot))
		prot_none = True

	return (prot_r, prot_w, prot_x)

# flags is the "flags" argument to an mmap() syscall,
# as shown in strace output; e.g., MAP_PRIVATE|MAP_ANONYMOUS or
# MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE.
# Returns: a tuple of booleans:
#   (map_p, map_s, map_anon, map_fixed, map_hugetlb)
def extract_map_bools(flags):
	tag = 'extract_map_bools'

	map_p = False
	map_s = False
	map_anon = False
	map_fixed = False
	map_hugetlb = False
	if "MAP_SHARED" in flags and "MAP_PRIVATE" in flags:
		print_error_exit(tag, ("invalid flags: both private and "
		    "shared! {0]").format(flags))
	if "MAP_SHARED" in flags:
		map_s = True
		map_p = False
	elif "MAP_PRIVATE" in flags:
		map_p = True
		map_s = False
	else:
		print_error_exit(tag, ("invalid flags: neither private nor "
		    "shared! {0}").format(flags))
	if "MAP_ANON" in flags:
		map_anon = True
	if "MAP_FIXED" in flags:
		map_fixed = True
	if "MAP_HUGETLB" in flags:
		map_hugetlb = True

	return (map_p, map_s, map_anon, map_fixed, map_hugetlb)

def construct_perms_key2(prot_r, prot_w, prot_x, map_s, map_anon):
	tag = 'construct_perms_key2'

	if prot_r:
		key = "r"
	else:
		key = "-"
	if prot_w:
		key += "w"
	else:
		key += "-"
	if prot_x:
		key += "x"
	else:
		key += "-"
	if map_s:
		key += "s"
	else:
		key += "p"
	if map_anon:
		key += "a"
	else:
		key += "f"
	
	if key not in PERMS_KEYS:
		print_error_exit(tag, ("whoa: constructed key={0} not in "
			"PERMS_KEYS={1}").format(key, PERMS_KEYS))

	return key

def perms_key_is_file_backed(perms_key):
	return 'f' in perms_key

def perms_key_is_anon(perms_key):
	return 'a' in perms_key

def perms_key_is_writeable(perms_key):
	return 'w' in perms_key

def perms_key_is_private(perms_key):
	return 'p' in perms_key

def perms_key_is_cow(perms_key):
	return ('w' in perms_key and 'p' in perms_key)

def perms_key_is_guard_region(perms_key):
	if ('r' not in perms_key and
		'w' not in perms_key and
		'x' not in perms_key):
		return True
	return False

def change_perms_key(orig_perms_key, prot_r, prot_w, prot_x):
	tag = 'change_perms_key'

	if orig_perms_key not in PERMS_KEYS:
		print_error_exit(tag, ("orig_perms_key {0} not in PERMS_KEYS "
			"{1}").format(orig_perms_key, PERMS_KEYS))
	
	# This works for perms_keys as they are right now, but isn't
	# particularly robust if the perms_key format changes in the
	# future...
	if "s" in orig_perms_key:
		map_s = True
	else:
		map_s = False
		if not "p" in orig_perms_key:
			print_error_exit(tag, ("expected 'p' in orig_perms_key "
				"{0}").format(orig_perms_key))
	if "a" in orig_perms_key:
		map_anon = True
	else:
		map_anon = False
		if not "f" in orig_perms_key:
			print_error_exit(tag, ("expected 'f' in orig_perms_key "
				"{0}").format(orig_perms_key))
	
	new_perms_key = construct_perms_key2(prot_r, prot_w, prot_x,
		map_s, map_anon)
	print_debug(tag, ("prot r={0}, w={1}, x={2}: perms_key {3} -> {4}").format(
		prot_r, prot_w, prot_x, orig_perms_key, new_perms_key))

	return new_perms_key

# Copies a proc file to a normal file. To copy the proc file, this method
# opens it, reads it line by line, and writes it to the normal file; I
# don't think that a standard "cp" command works on proc files.
# This method currently does no error checking.
def copy_proc_file_old(src_fname, dst_fname):
	tag = "copy_proc_file_old"

	try:
		src_f = open(src_fname, 'r')
	except IOError:
		# This happened once for chromium-browser - it calls "/bin/sh
		# /usr/bin/xdg-settings check default-web-browser
		# chromium-browser.desktop", which causes a series of subprocesses
		# to be invoked, which sometimes die in iteration 001 before we
		# can read their proc files.
		print_warning(tag, ("got IOError while attempting to open "
			"proc file {0} - process must have died before we could read "
			"its proc file").format(src_fname))
		return
	try:
		line = src_f.readline()
		dst_f = open(dst_fname, 'w')  # trigger IOError on previous line first
		while line:
			dst_f.write(line)
			line = src_f.readline()
		dst_f.close()
	except IOError:
		# Happens for /usr/lib/chromium-browser/chromium-browser-sandbox
		# process, for example :( For some reason most of its /proc files
		# have "--r--r--r root root" permission.
		print_warning(tag, ("got IOError while attempting to read "
			"proc file {0} - does it have root-only permissions?").format(
			src_fname))

	src_f.close()
	return

# Takes a list of "translation sizes" (size of a potential translation
# entry in bytes, e.g. [4096, 2097152] for 4 KB pages and 2 MB pages)
# and returns the number of translation entries needed to track the
# vma's virtual-to-physical mappings.
# IMPORTANT: the list of txln_sizes should be passed into this method
# in ASCENDING order (smallest size to largest).
# Returns: a list with len(txln_sizes) entries, where each entry in the
# list equals the number of translation entries of the corresponding
# size that would be used to map the vma. Returns None on error.
def txln_entries_needed(txln_sizes, vma):
	tag = 'txln_entries_needed'

	# todo: check if input list is actually sorted...
	sizes_reversed = list(reversed(sorted(txln_sizes)))
	#print_debug(tag, ("sizes_reversed: {}").format(sizes_reversed))

	sizeleft = vma.length
	idx = 0
	returnlist = [0] * len(sizes_reversed)

	while sizeleft > 0:
		if idx >= len(sizes_reversed):
			print_error_exit(tag, ("bug, idx {} out of range").format(
				idx))

		txln_size = sizes_reversed[idx]
		if txln_size <= sizeleft:
			entries_this_size = int(sizeleft / txln_size)
			returnlist[idx] = entries_this_size
			sizeleft2 = sizeleft % txln_size
			sizeleft -= (entries_this_size * txln_size)
			if sizeleft != sizeleft2:
				print_error_exit(tag, ("sanity check failed: "
					"sizeleft={}, sizeleft2={}").format(sizeleft,
					sizeleft2))

		idx += 1
		if idx == len(sizes_reversed) and sizeleft != 0:
			# I'm not sure if this will happen or not, given the
			# interface that mmap() enforces... but if it does, just
			# add one more entry of the smallest size.
			print_unexpected(False, tag, ("vma.length {} didn't fit "
				"evenly into sizes {}?").format(vma.length, txln_sizes))
			returnlist[idx-1] += 1
			sizeleft = 0

	returnlist.reverse()  # match input list!

	#print_debug(tag, ("vma.length={}: mapped with {} pages").format(
	#	vma.length, returnlist))
	return returnlist

# Calculates the number of pages of the specified pagesize (bytes) that
# would be needed to map a virtual region (vma) of the specified length.
# If the vma's length cannot be mapped
# as an exact multiple of the pagesize, then one full page of pagesize
# is used to map the remainder, and the "empty" part of that last full
# page is counted as internal fragmentation.
# Returns a tuple: (numpages, fragmentation), or None on error (only if
#   an invalid arg was passed).
def pages_needed(pagesize, vmalength):
	tag = 'pages_needed'

	if not pagesize or pagesize < 1 or not vmalength or vmalength < 2:
		print_error(tag, ("invalid arg: pagesize={}, vmalength={}").format(
			pagesize, vmalength))
		return None

	pagesneeded = int(vmalength / pagesize)
	remainder = vmalength % pagesize
	if remainder == 0:
		fragmentation = 0
	else:
		pagesneeded += 1
		fragmentation = pagesize - remainder
	
	#print_debug(tag, ("basepagesize {}: {} pages to map {} vma, with "
	#	"{} bytes of fragmentation").format(pretty_bytes(pagesize),
	#	pagesneeded, pretty_bytes(vmalength), fragmentation))
	return (pagesneeded, fragmentation)

# Possible values for sortby: 'start_addr', 'size'.
def active_vmas_to_maps_file(active_vmas, outputdir, descr,
		sortby='start_addr'):
	tag = 'active_vmas_to_maps_file'

	fname = "{}/maps-{}".format(outputdir, descr)
	try:
		f = open(fname, 'w')
	except:
		print_error(tag, ("error opening file for writing, "
			"outputdir={}, descr={}").format(outputdir, descr))
		return
		
	if sortby == 'size':
		sorted_vmas = sorted(active_vmas, key=lambda vma: vma.length)
	else:
		sorted_vmas = sorted(active_vmas, key=lambda vma: vma.start_addr)
	print_debug(tag, ("writing {} vmas to maps file {}").format(
		len(sorted_vmas), fname))
	if len(active_vmas) != len(sorted_vmas):
		print_error_exit(tag, ("len(active_vmas)={}, but len(sorted"
			"_vmas)={} ?!?!").format(len(active_vmas), len(sorted_vmas)))
	for vma in sorted_vmas:
		f.write(("{}\n").format(vma.to_str_maps_format()))

	f.close()
	return

# Returns True if the filename argument should be considered as a shared
# library object file, or False if it represents some other file.
# IMPORTANT: this method should be combined with perms_key_is_writeable()
# (or perms_key_is_cow()? ...): if a vma is writeable, then even if it
# is used for mapping a shared library file, it probably should not be
# counted as "shared" because if/when it's modified a separate copy of
# it will be made for the process' address space.
def filename_is_shared_lib(fname):
	tag = 'filename_is_shared_lib'

	if fname is None or len(fname) == 0:
		return False

	# After examining all of the maps outputs (at the point when the
	# virtual memory size was the greatest) for 8+ applications from
	# my test suite, it looks like we can determine whether or not a
	# vma should be counted as a "shared object" / "shared library"
	# simply by looking at its filename. These rules were developed
	# on host "verbena", and I'd expect them to work on any Ubuntu
	# distribution. Where necessary, these rules are "conservative":
	# if it's not *definitely* a shared library, then tend to return
	# False.
	#
	# The rules (all must be met) are simple for now:
	#   Found somewhere under /usr/lib/x86_64-linux-gnu/ or
	#     /lib/x86_64-linux-gnu/, or my own special lib directories,
	#     /home/pjh/research/virtual/gcc-testinstall-notailcalls and
	#     /home/pjh/research/virtual/glibc-testinstall-notailcalls
	#   Filename ends in .so* (e.g. .so, .so.0.1502.0, .so.7.0.1, etc.)
	#   r--p, r-xp, and ---p regions only (not checked here though;
	#     see comments above this method)
	#
	# Considerations made when examining file mappings in the app and
	# writing this method:
	#   Some applications install their own libraries, but they usually
	#   go into a special directory under /lib or /usr/lib; for example:
	#     /usr/lib/php5
	#     /usr/lib/apache2
	#     /opt/google/chrome
	#     /usr/lib/jvm
	#     /usr/lib/mozilla
	#     /usr/lib/firefox
	#   Because these libraries are "application-specific", we don't
	#   want to count them as shared libraries here; they should be
	#   considered part of the standard application code, but just
	#   happen to be loaded dynamically.
	#
	#   A bunch of libraries are found directly under /usr/lib/, but
	#   these are used rarely apparently; one example is 
	#   /usr/lib/libmcrypt.so.4.4.8 for apache. (Also
	#   /usr/lib/libapr*, which are apache-specific for sure.)
	#   Noticed a couple others in this directory used for openoffice.
	#
	#   Some libs that appear to be exceptions the rules above and
	#   could probably be counted as shared libs if we wanted,
	#   but we won't because these files are tiny and we're being
	#   conservative):
	#     /usr/lib/jvm/java-7-openjdk-amd64/jre/lib/amd64/IcedTeaPlugin.so
	#       (A java lib, but used by firefox)
	#   Some libs that perhaps should exceptions to the rules above
	#   and NOT counted as shared libs:
	#     /lib/x86_64-linux-gnu/libnss*.so
	#       This appears to be distributed with / installed by firefox,
	#       and I haven't seen it used by any other apps (yet...).
	#
	#   What about files under /usr/share ? These are always mapped
	#   as read-only, and by "definition" it seems like they should
	#   count as shared files...

	debugthis = True
	prefixmatch = False
	suffixmatch = None
	suffix_regex = re.compile(r"\.so(\.[\d.]+)?$")

	#print_debug2(debugthis, tag, ("sysconf.SHARED_LIB_DIRS: "
	#	"{}").format(sysconf.SHARED_LIB_DIRS))
	for D in sysconf.SHARED_LIB_DIRS:
		if fname.startswith(D):
			prefixmatch = True
			break

	if prefixmatch:
		suffixmatch = suffix_regex.search(fname)
		#print_debug2(debugthis, tag, ("{}: prefixmatch={}, "
		#	"suffixmatch={}").format(fname, prefixmatch, suffixmatch))
	else:
		#print_debug2(debugthis, tag, ("{}: prefixmatch={}").format(
		#	fname, prefixmatch))
		pass

	if prefixmatch and suffixmatch:
		print_debug2(debugthis, tag, ("    SHAREDLIB: {}").format(
			fname))
		return True
	
	print_debug2(debugthis, tag, ("NOT SHAREDLIB: {}").format(fname))
	return False

# Returns True if the filename argument should be considered as a shared
# file (other than shared libs which are already identified by
# filename_is_shared_lib()). IMPORTANT: the caller should also check
# that the file is mapped as read-only!
def filename_is_non_lib_shared_dir_file(fname):
	tag = 'filename_is_non_lib_shared_dir_file'

	if fname is None or len(fname) == 0:
		return False

	# See detailed notes in filename_is_shared_lib(). For now, this
	# method returns True only for files under /usr/share.
	# In my experience these files are always mapped into the address
	# space as read-only, but the caller should check the perms key
	# to be sure.
	
	debugthis = True
	prefixmatch = False

	for D in sysconf.USR_SHARE_DIRS:
		if fname.startswith(D):
			prefixmatch = True
			break

	if prefixmatch:
		print_debug2(debugthis, tag, ("    SHAREDFILE: {}").format(
			fname))
		return True
	
	print_debug2(debugthis, tag, ("NOT SHAREDFILE: {}").format(fname))
	return False

# Used by various plots and other parts of analysis (i.e. track_vm_size())
# to ignore vmas used for shared libs, shared read-only files, or
# guard regions (each of these can be enabled/disabled with the IGNORE_*
# flags at the top of this file).
#
# How did I validate the use of this method?
#   * I examined the (nearly) entire analysis + plot output for hello-world
#     (dynamically linked) and verified that the vma counting done in both
#     the vmacount plot and the track_vm_size() method matched each other
#     and matched the maps files that were output at the time of maximum
#     vma count (analyze_point_in_time()).
#   * I did a similar validation for a firefox trace, which uses a ton
#     of shared libraries and which is actually mildly multi-process
#     (e.g. dbus processes). I compared the maximum vma counts output
#     by the plot and track_vm_size() to the maps file output at the time
#     of maximum vma count; since ignore_vma() is not called for the
#     maps output method (I don't think it ever really should be), I
#     manually counted the various shared lib, shared file, and guard
#     regions in the maps file, and verified that when those were
#     discounted, the maximum number of remaining vmas matched the plot /
#     track output exactly.
def ignore_vma(vma):
	tag = 'ignore_vma'

	if IGNORE_SHARED_LIBS and vma.is_shared_lib():
		print_debug(tag, ("ignoring shared lib vma {}").format(vma))
		return True
	if IGNORE_SHARED_FILES and vma.is_non_lib_shared_dir_file():
		print_debug(tag, ("ignoring shared file vma {}").format(vma))
		return True
	if IGNORE_GUARD_REGIONS and vma.is_guard_region():
		print_debug(tag, ("ignoring guard region vma {}").format(vma))
		return True
	return False

heap_label = 'Heap'
anon_label = 'Anon'
otheranon_label = 'OtherAnon'
other_label = 'Other'
file_label = 'File'
privatefile_label = 'PrivateFile'
sharedfile_label = 'SharedFile'
guard_label = 'Guard'
sharedlib_label = 'Libs'   #'SharedLib'
normal_label = 'Normal'

# The order of these categories is important for categories_plotfn():
# the 0th element in this list will be the bottom of the stack or the
# left-most column for each app, then the 1st element, and so on.
VMA_CATEGORIES = [
		anon_label,
		file_label,
		guard_label,
		sharedlib_label
	]

# Returns a list of categories that this vma falls into. This method
# is currently intended for high-level, *non-overlapping* categories
# (so the length of the list returned is always exactly 1).
def classify_vma(vma):
	tag = 'classify_vma'

	# IMPORTANT: make sure that these categories are found in
	# VMA_CATEGORIES!
	categories = []
	if vma.is_shared_lib():
		categories.append(sharedlib_label)
	#elif vma.is_non_lib_shared_dir_file():
	#	categories.append('Shared file')
	elif vma.is_guard_region():
		categories.append(guard_label)
	elif vma.is_file_backed():
		categories.append(file_label)
		#if vma.is_private():
		#	categories.append(privatefile_label)
		#else:
		#	categories.append(sharedfile_label)
	else:
		#if vma.is_writeable():
		#	# Is this exactly right? What about: rwx? Should that
		#	# count as "heap"?
		#	categories.append(heap_label)
		#else:
		#	categories.append(otheranon_label)
		categories.append(anon_label)
	
	#print_debug(tag, ("category {} for vma {}").format(
	#	categories, vma))

	return categories

# Returns the closest power of 2 that is greater than n, starting from
# a minimum mapping size (currently set to the base page size, 4 KB).
# If n itself is a power of 2, then n will be returned.
def nextpowerof2(n):
	tag = 'nextpowerof2'

	min_mapping_size = PAGE_SIZE_4KB

	p = min_mapping_size
	if n < p:
		print_error_exit(tag, ("invalid arg {} - min_mapping_size is "
			"{}!").format(n, min_mapping_size))
	while p < n:
		p *= 2

	return p

# Labels + sizes used for plots:
# Easiest to just define these statically, so there are no gaps in
# the list...
VMA_MAX_ORDER = 32  # 2^32 = 4 GB
VMA_SIZES = []
VMA_SIZES_LABELS = []
for i in range(12, VMA_MAX_ORDER + 1):  # up to 2^32 = 4 GB
	x = int(2**i)
	VMA_SIZES.append(x)
	VMA_SIZES_LABELS.append(pretty_bytes(x, 0))

VMA_SIZES_MAX = VMA_SIZES[-1]
VMA_SIZES_GREATER_LABEL = "> {}".format(VMA_SIZES_LABELS[-1])
VMA_SIZES_LABELS.append(VMA_SIZES_GREATER_LABEL)
  # ok, ready to be used for plot x-axis labels

# Mapping between the two lists above (doesn't include VMA_SIZES_GREATER_LABEL
# though).
VMA_SIZES_MAP = {}
for i in range(len(VMA_SIZES)):
	VMA_SIZES_MAP[VMA_SIZES[i]] = VMA_SIZES_LABELS[i]

if __name__ == '__main__':
	print_error_exit("not an executable module")

