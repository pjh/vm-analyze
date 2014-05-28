# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
from trace.simulate_segments_lib import *
import trace.vm_common as vm

module_sep = '->'   # "separator"
mod_fn_sep = '+'
fn_sep = module_sep
badtrace_str = 'USR'
MODULE_KERNEL = 'kernel(setup-teardown)'
MODULE_ANON = 'anon-mapping'

#LARGE_VMA_THRESHOLD = 2*1024*1024*1024 + 1  # find vmas that round up to 4 GB
LARGE_VMA_THRESHOLD = 128*1024*1024 + 1  # find vmas that round up to 256 MB
  # vm_mappings beyond this many bytes will have a message printed.
UNKNOWN_MODULE = 'unknown_module'
UNKNOWN_FN = 'fn-in-unknown-module'

'''
Class that mimics the "VMAs" (virtual memory areas) that the Linux OS
keeps track of. Currently these are the objects held by our simulated
"segment table." vm_mappings are current immutable.
'''
class vm_mapping:
	tag = "class vm_mapping"

	# Members:
	start_addr = None
	length = None
	perms_key = None
	offset = None
	dev_major = None
	dev_minor = None
	inode = None
	filename = None
	vma_op = None
	seg_size = None
	timestamp = None
	read_count = None
	write_count = None
	read_count_quantum = None
	write_count_quantum = None
	creator_module = None
	creator_fn = None
	is_unmapped = None
	unmap_timestamp = None
	unmap_op = None
	kernel_fn = None   # kernel function that created this vma
	appname = None     # name of app this vma is associated with
	shared_lib = None
	shared_dir_file = None

	def __init__(self, start_addr, length, perms_key, seg_size,
		vma_op=None, offset=0, dev_major=0, dev_minor=0, inode=0,
		filename='', timestamp=-1, module='', fn='', kernel_fn='',
		unmarshal_tsv_str=None, appname=None):
		tag = "{0}.__init__".format(self.tag)
		global LARGE_VMA_THRESHOLD
		global UNKNOWN_MODULE
		global UNKNOWN_FN

		if unmarshal_tsv_str:
			self.unmarshal_tsv(unmarshal_tsv_str)
			return

		if (not start_addr or length < 0 or not perms_key or not seg_size
			#or length < vm.PAGE_SIZE_BYTES
			or perms_key not in vm.PERMS_KEYS or seg_size < min_segment_size):
			print_error_exit(tag, ("invalid length {0} or perms_key "
				"{1} or seg_size {2} or start_addr {3}").format(length,
				perms_key, seg_size, hex(start_addr)))
		if length == 0:
			print_debug(tag, ("creating mapping with length 0 - this "
				"had better be an initial stack mapping from "
				"__bprm_mm_init()!").format())
		if length < vm.PAGE_SIZE_BYTES:
			#print_warning(tag, ("creating mapping with length of {0} bytes, "
			#	"which is less than expected minimum mapping ({1} "
			#	"bytes)").format(length, vm.PAGE_SIZE_BYTES))
			print_debug(tag, ("creating mapping with length of {0} bytes, "
				"which is less than expected minimum mapping ({1} "
				"bytes)").format(length, vm.PAGE_SIZE_BYTES))
		if length >= LARGE_VMA_THRESHOLD:
			print_debug(tag, ("creating vma with length {0}, which is "
				"beyond arbitrary LARGE_VMA_THRESHOLD").format(
				pretty_bytes(length)))
		if vma_op and vma_op not in VMA_OP_TYPES:
			print_error_exit(tag, ("got vma_op={0} not in list of "
				"VMA_OP_TYPES={1}").format(vma_op, VMA_OP_TYPES))

		self.start_addr = start_addr
		self.length = length
		self.perms_key = perms_key
		self.seg_size = seg_size
		self.offset = offset
		self.dev_major = dev_major
		self.dev_minor = dev_minor
		self.inode = inode
		self.filename = filename
		self.vma_op = vma_op
		self.timestamp = timestamp
		self.read_count = 0
		self.write_count = 0
		self.read_count_quantum = 0
		self.write_count_quantum = 0
		if not module or module == "":
			self.creator_module = UNKNOWN_MODULE
		else:
			self.creator_module = module
		if not fn or fn == "":
			self.creator_fn = UNKNOWN_FN
		else:
			self.creator_fn = fn
		self.is_unmapped = False
		self.unmap_timestamp = None
		self.unmap_op = None
		self.kernel_fn = kernel_fn
		self.appname = appname

		# Call helper methods just once and set permanent boolean
		# values in the vma - trade time for space...
		self.shared_lib = is_shared_lib_vma(self)
		self.shared_dir_file = is_shared_dir_file_vma(self)

		return

	def end_addr(self):
		return self.start_addr + self.length - 1

	def __str__(self):
		begin_addr = hex_no_X(self.start_addr).zfill(8)
		end_addr = hex_no_X(self.start_addr + self.length).zfill(8)
		perms = self.perms_key[0:4]
		offset = hex_no_X(self.offset).zfill(8)
		dev_major = hex_no_X(self.dev_major).zfill(2)
		dev_minor = hex_no_X(self.dev_minor).zfill(2)
		inode = self.inode
		filename = self.filename
		if self.is_unmapped:
			mapped = "unmapped"
		else:
			mapped = "mapped"
		s = ("{}-{} [{}] {} {}, {} {} {}").format(
			begin_addr, end_addr, pretty_bytes(self.length),
			perms, filename, self.vma_op, mapped, self.unmap_op)
		return s

	def to_str(self):
		s = ("[{0}, {1}] length={2} ({3}) perms_key='{4}' "
			"seg_size={5} ({6}), created by fn={7}").format(
			hex(self.start_addr),
			hex(self.start_addr + self.length - 1),
			pretty_bytes(self.length),
			hex(self.length), self.perms_key, self.seg_size,
			hex(self.seg_size),
			self.creator_fn)
		return s

	def to_str_maps_format(self):
		begin_addr = hex_no_X(self.start_addr).zfill(8)
		end_addr = hex_no_X(self.start_addr + self.length).zfill(8)
		perms = self.perms_key[0:4]
		offset = hex_no_X(self.offset).zfill(8)
		dev_major = hex_no_X(self.dev_major).zfill(2)
		dev_minor = hex_no_X(self.dev_minor).zfill(2)
		inode = self.inode
		filename = self.filename
		s = ("{0}-{1} {2} {3} {4}:{5} {6} {7}").format(
			begin_addr, end_addr, perms, offset, dev_major, dev_minor,
			inode, filename)
		return s

	def to_str_maps_plus(self):
		mapstr = self.to_str_maps_format()
		mapstr += "\t{0}".format(self.creator_module)
		mapstr += "\t{0}".format(self.creator_fn)
		mapstr += "\t{0}".format(self.timestamp)
		return mapstr

	def is_equal(self, other):
		if not other:
			print_warning("", ("other passed to is_equal() is None; just "
				"returning False. self = {0}").format(self.to_str()))
			return False
		if self.start_addr == other.start_addr:
			if (self.length == other.length and
				self.perms_key == other.perms_key and
				self.seg_size == other.seg_size):
				return True
			else:
				print_error_exit("", ("self.start_addr matches "
					"other.start_addr, but entries are not identical in "
					"other ways! self [{0}]; other [{1}]").format(
					self.to_str(), other.to_str()))
		return False

	def access(self, op):
		tag = "{0}.access".format(self.tag)

		if op == 'Read':
			self.read_count_quantum += 1
			self.read_count += 1
		elif op == 'Write':
			self.write_count_quantum += 1
			self.write_count += 1
		else:
			print_error_exit(tag, ("unexpected op={0}").format(op))
		print_debug(tag, ("vma [{0}, {1}]: {2} -> counts "
			"= ({3}, {4}) this quantum, ({5}, {6}) ever.").format(
			self.start_addr, self.end_addr(), op,
			self.read_count_quantum, self.write_count_quantum,
			self.read_count, self.write_count))
		return

	# Returns a tuple of the vma's (read_count_quantum,
	# write_count_quantum, read_count, write_count) before resetting
	# the quantum counts back to 0.
	def reset_access(self):
		tag = "{0}.reset_access".format(self.tag)

		(rq, wq, r, w) = (self.read_count_quantum, self.write_count_quantum,
			self.read_count, self.write_count)
		self.read_count_quantum = 0
		self.write_count_quantum = 0
		return (rq, wq, r, w)

	def is_file_backed(self):
		return vm.perms_key_is_file_backed(self.perms_key)

	def is_anonymous(self):
		return vm.perms_key_is_anon(self.perms_key)

	def is_guard_region(self):
		return vm.perms_key_is_guard_region(self.perms_key)

	def is_private(self):
		return vm.perms_key_is_private(self.perms_key)

	def is_writeable(self):
		return vm.perms_key_is_writeable(self.perms_key)

	def is_shared_lib(self):
		return self.shared_lib

	def is_non_lib_shared_dir_file(self):
		return self.shared_dir_file

	def is_unmapped(self):
		return self.is_unmapped

	# In addition to the timestamp when this vma was unmapped, save the
	# operation (free, resize, relocation, access_change, flag_change
	# (not alloc!)) that caused the unmapping! This can be used later
	# to determine whether or not this is a "true" unmapping (i.e. iff
	# the unmap_op is 'free') that should reduce a count of vmas in
	# a process, for example, or if this is an unmapping that will
	# be followed by a remap (i.e. the unmap_op is 'resize',
	# 'relocation', 'access_change', or 'flags_change').
	def mark_unmapped(self, timestamp, op):
		self.is_unmapped = True
		self.unmap_timestamp = timestamp
		self.unmap_op = op
		return

	# Fields of the vma that we want to save and restore go into
	# marshal_fields - this list establishes the order the fields will
	# appear in in the tsv line. Then, fields that need to be converted
	# from ints/bools to strings after unmarshalling go into the _ints and
	# _bools lists. These strings must exactly match the names of class
	# members set above.
	#
	# This technique is a little hacky - directly using the Python
	# pickle class might be a better idea since it would keep track
	# of type information automatically, but I like the idea of having
	# my own human-readable strings written out to files for marshalling.
	marshal_fields = ['timestamp', 'start_addr', 'length', 'perms_key',
		'offset', 'dev_major', 'inode', 'filename', 'vma_op',
		'seg_size', 'creator_module', 'creator_fn', 'is_unmapped',
		'unmap_timestamp', 'unmap_op', 'kernel_fn', 'appname', ]
	marshal_fields_ints = ['timestamp', 'start_addr', 'length',
		'offset', 'dev_major', 'inode', 'seg_size', 'unmap_timestamp', ]
	marshal_fields_bools = ['is_unmapped', ]

	# Returns a tab-separated string suitable for writing to a file.
	def marshal_tsv(self):
		tag = 'marshal_tsv'

		# Note: the Python "pickle" class / operations would also be
		# suitable for this, but for now just using my own human-readable
		# string is sufficient.
		#   http://docs.python.org/3/library/pickle.html#module-pickle
		# Get member given string: http://stackoverflow.com/a/1167419/1230197
		s = None
		for field in self.marshal_fields:
			if not s:
				s = "{}".format(getattr(self, field))
			else:
				s += "\t{}".format(getattr(self, field))
		print_debug(tag, ("marshalled: {}").format(s))
		return s

	def marshal_header(self):
		return '\t'.join(self.marshal_fields)

	# Initializes the members of self using the values in tsv_str, which
	# should come from a prior call to marshal_tsv().
	def unmarshal_tsv(self, tsv_str):
		tag = 'unmarshal_tsv'

		in_fields = tsv_str.split('\t')
		if len(in_fields) != len(self.marshal_fields):
			print_error_exit(tag, ("{} fields in marshal_fields list, "
				"but got {} in_fields from tsv_str {}").format(
				len(self.marshal_fields), len(in_fields), tsv_str))

		for i in range(0, len(in_fields)):
			# http://docs.python.org/3/library/functions.html#setattr
			setattr(self, self.marshal_fields[i], in_fields[i])
			print_debug(tag, ("set self.{} = {}").format(
				self.marshal_fields[i],
				getattr(self, self.marshal_fields[i])))

		# All of the values that we just set are strings - convert some
		# of them to ints and bools:
		for intfield in self.marshal_fields_ints:
			f = getattr(self, intfield)
			setattr(self, intfield, int(f))
		for boolfield in self.marshal_fields_bools:
			f = getattr(self, boolfield)
			if f == 'True':
				b = True
			elif f == 'False':
				b = False
			else:
				print_error(tag, ("expect field {} to be 'True' or 'False', "
					"but is {}").format(boolfield, f))
			setattr(self, boolfield, b)

		return

# "Static methods" for vm_mapping objects are below. 

# Returns True if this is a NON-WRITEABLE shared library vma. (So guard
# regions for shared libs will return True here).
def is_shared_lib_vma(vma):
	tag = 'is_shared_lib_vma'

	# Should we check perms_key_is_writeable() or
	# perms_key_is_cow() here? In my experience, if
	# filename_is_shared_lib() returns True, then
	# it doesn't matter (a writeable shared lib vma
	# mapping will always be private/COW as well).
	if (not vm.perms_key_is_writeable(vma.perms_key) and
			vm.filename_is_shared_lib(vma.filename)):
		#print_debug(tag, ("    shared lib vma: {} {}").format(
		#	vma.perms_key, vma.filename))
		return True
	#if vma.filename and len(vma.filename) > 0:
	#	print_debug(tag, ("non-shared lib vma: {} {}").format(
	#		vma.perms_key, vma.filename))
	return False

# Returns True if this is a non-writeable mapping of a file located
# in a well-known shared file directory (e.g. /usr/share).
def is_shared_dir_file_vma(vma):
	if (not vm.perms_key_is_writeable(vma.perms_key) and
			vm.filename_is_non_lib_shared_dir_file(vma.filename)):
		return True
	return False

# Finds the vm_mapping in the segment table that matches the specified
# address. If the starts_at argument is True, then this method will only
# return a vm_mapping if the mapping STARTS exactly at the specified address;
# otherwise, the vm_mapping that CONTAINS the address will be returned.
# Returns: when found, the vm_mapping entry is returned; if not found, then
# None will be returned. If the remove arg is True, then the proc_info that
# was passed in will have been modified.
# If the optional remove arg is set to True, then the found entry will be
# removed from the table.
# Note: the "contains" search is based on the size of the vm mapping that
# the application made, not on the size of the segment that was assigned to
# this mapping.
# IMPORTANT: the caller of this method with remove=True must also update
# the segset; this method only updates the vmatable.
def find_vm_mapping(proc_info, search_addr, starts_at, remove=False):
	tag = "find_vm_mapping"

	vmatable = proc_info.get_vmatable()

	try:
		if remove:
			entry = vmatable.pop(search_addr)
		else:
			entry = vmatable[search_addr]
		#print_debug(tag, ("found mapping [{0}, {1}] that exactly starts at "
		#	"search_addr {2}; remove={3}").format(hex(search_addr),
		#	hex(search_addr + entry.length - 1), hex(search_addr),
		#	remove))
		return entry    # starts_at doesn't matter
	except KeyError:
		if starts_at:
			return None
		# This would be more efficient if the segment table were stored as
		# a BST, rather than a dictionary...
		for entry in vmatable.values():
			if (entry.start_addr < search_addr and
				search_addr <= entry.start_addr + entry.length - 1):
				if remove:
					del vmatable[entry.start_addr]
				#print_debug(tag, ("found mapping [{0}, {1}] that contains "
				#	"search_addr {2}; remove={3}").format(
				#	hex(entry.start_addr),
				#	hex(entry.start_addr + entry.length - 1),
				#	hex(search_addr), remove))
				return entry

	return None

# Returns an array containing all of the vm_mappings in the
# vmatable that contain an address within the specified range
# (inclusive). The mappings in the returned array are guaranteed
# to be sorted by increasing start_addr. Actually, the mappings
# are returned in tuples along with a "layout" string, which is
# one of:
#   "overlaps_left"  - the mapping overlaps the search range to the left
#   "overlaps_range" - the mapping overlaps the entire range
#   "overlaps_right" - the mapping overlaps the search range to the right
#   "within_range"   - the mapping is entirely contained within the search range
# If no mappings are found, an empty array [] is returned.
# None is returned on error.
#
# Note that this function runs in O(n log n) time - it is slow.
def find_vm_mappings_in_range(proc_info, range_start, range_end):
	tag = "find_vm_mappings_in_range"

	vmatable = proc_info.get_vmatable()

	found = []
	for key in sorted(vmatable.keys()):
		mapping = vmatable[key]
		start = mapping.start_addr
		end = mapping.end_addr()

		# There are five possible "layouts" of the mapping's range
		# relative to the search range:
		if start < range_start:
			if end < range_start:
				layout = ""
			elif end < range_end:
				layout = "overlaps_left"
			else:
				layout = "overlaps_range"
		elif start == range_start:
			if end < range_end:
				layout = "within_range"
			else:
				# This case includes start == range_start and end == range_end
				layout = "overlaps_range"
		elif start <= range_end:
			if end <= range_end:
				layout = "within_range"
			else:
				layout = "overlaps_right"
		else:
			layout = ""

		if layout != "":
			found.append((mapping, layout))
			print_debug(tag, ("mapping [{0}, {1}] found to overlap "
				"search range [{2}, {3}] - layout \"{4}\"").format(
				hex(mapping.start_addr), hex(mapping.end_addr()),
				hex(range_start), hex(range_end), layout))
	
	return found

# Splits the specified vm_mapping into one, two or three different / separate
# mappings. The new / modified / removed mapping(s) are returned in an array
# of length 1, 2 or 3; the mappings are NOT directly updated in the segment
# table. The caller of this function should remove the original mapping and
# segment, and then update the vmatable and segset with the results from
# this method.
# 
# split_addr is the address where the split should be performed. This address
#   must be an address within an existing mapping (either the starting
#   address or somewhere in the middle).
# length is the length of the region to be modified / removed.
# unmap should be set to True if the specified region is to be removed.
# perms_key must be set to the new permissions to use for the modified
#   region is unmap is set to False.
# 
# Returns: an array containing the updated mappings resulting from the
# split (1, 2 or 3 of them) on success; on error (i.e. the specified
# address did not match any current mappings), None is returned.
def split_vm_mapping(proc_info, split_addr, length, unmap, to_seg_size,
	perms_key=None):
	tag = "split_vm_mapping"

	# Start by finding the existing entry. DON'T REMOVE IT here, however;
	# the caller will find and remove it from the segment table.
	orig_entry = find_vm_mapping(proc_info, split_addr, starts_at=False,
		remove=False)
	if orig_entry is None:
		return None
	orig_end_addr = orig_entry.start_addr + orig_entry.length - 1
	split_end_addr = split_addr + length - 1
	print_debug(tag, ("orig_entry: {0}").format(orig_entry.to_str()))
	print_debug(tag, ("splitting mapping [{0}, {1}] (length {2}) at "
		"subregion [{3}, {4}] (length={5}); unmap={6}, perms_key={7}").format(
		hex(orig_entry.start_addr), hex(orig_end_addr), orig_entry.length,
		hex(split_addr), hex(split_end_addr), length,
		unmap, perms_key))

	# Determine whether or not this mapping "split" is also going to
	# EXTEND the existing mapping beyond its current boundary. This must
	# definitely be allowed for re-protect operations (unmap = False),
	# as this has been seen in application traces (mmap() operations that
	# start at a specific address within an existing mapping, and extend
	# beyond the end of the current mapping). I'm not sure if it's legal
	# to make an munmap call with a length beyond the end of an existing
	# boundary, so this is not yet allowed in this function (but if it
	# turns out to be legal in the syscall, it should be really easy to
	# allow here).
	#   Well, it turns out that it is legal (and it does happen in app
	#   traces) to munmap beyond the end of an existing mapping. From
	#   munmap(2):
	#     ...It is not an error if the indicated range does not contain
	#     any mapped pages.
	if split_end_addr > orig_end_addr:
		extend = True
		print_error_exit(tag, ("disabling extend code in this function; "
			"handler it in caller instead!").format())
		print_debug(tag, ("extending orig_end_addr {0} to split_end_addr "
			"{1} with this unmap={2} operation").format(
			hex(orig_end_addr), hex(split_end_addr), unmap))
		test = find_vm_mapping(proc_info, split_end_addr, starts_at=False)
		if test is not None:
			#print_error_exit(tag, ("extended split_end_addr {0} actually "
			print_warning(tag, ("extended split_end_addr {0} actually "
				"lies within another mapping, {1} - are you kidding "
				"me??????").format(hex(split_end_addr), test.to_str()))
			print_warning(tag, ("ignoring this for now; means that unmapped "
				"region will remain!!").format())
	else:
		extend = False

	# Check a few other assertions:
	if unmap:
		if (orig_entry.start_addr == split_addr and
			orig_end_addr == split_end_addr):
			print_error_exit(tag, ("split called to unmap an entire mapping; "
				"this code path should never be hit, right?").format())
	else:
		# If not unmapping, then perms_key must be set:
		if not perms_key or perms_key not in vm.PERMS_KEYS:
			print_error_exit(tag, ("unmap set, but invalid perms_key="
				"{0}").format(perms_key))
	
	# First, create a "pre" mapping if we're splitting a mapping at an
	# address beyond its start address, and re-insert it into the segment
	# table.
	if split_addr > orig_entry.start_addr:
		# Note: inside this code block we have nothing to do with the
		# length of the incoming "split", so we don't have to worry
		# about an "extend".
		pre_length = split_addr - orig_entry.start_addr
		pre_seg_size = to_seg_size(pre_length)
		pre_entry = vm_mapping(orig_entry.start_addr, pre_length,
			orig_entry.perms_key, pre_seg_size)
		print_debug(tag, ("new pre_entry for vmatable: {0}").format(
			pre_entry.to_str()))
	else:
		if split_addr != orig_entry.start_addr:   # sanity check
			print_error_exit(tag, ("unexpected: split_addr {0} does not "
				"match orig_entry.start_addr {1}").format(hex(split_addr),
				hex(orig_entry.split_addr)))
		pre_entry = None
		print_debug(tag, ("split_addr matches orig_entry.start_addr {0}, so "
			"no pre_entry").format(hex(orig_entry.start_addr)))

	# If unmap is not set, then create a new entry that is a modification
	# of the original entry, with the new perms_key passed as an arg to
	# this method. If unmap is set, then we don't want to create a new
	# entry to replace the one that will be removed.
	if not unmap:
		# If extend is true, then this will still do the right thing,
		# since just the begin split_addr and the length are passed
		# to the vm_mapping() constructor. Then we just have to make
		# sure that no post_entry is constructed.
		mod_seg_size = to_seg_size(length)
		mod_entry = vm_mapping(split_addr, length, perms_key, mod_seg_size)
		print_debug(tag, ("modified mod_entry for vmatable: "
			"{0}").format(mod_entry.to_str()))
	else:
		mod_entry = None
		print_debug(tag, ("unmap=True, so not modifying+replacing the "
			"orig_entry").format())

	# Finally, create a "post" mapping for the un-modified region beyond
	# the end address of the modified region, if it exists.
	# If extend is true, then split_end_addr must be > orig_end_addr,
	# so we will NOT create a post_entry, which is what we want here;
	# the mod_entry took care of the extend, and there may or may not
	# be a pre_entry.
	if split_end_addr < orig_end_addr:
		post_start_addr = split_end_addr + 1
		post_length = (orig_end_addr + 1) - post_start_addr
		post_seg_size = to_seg_size(post_length)
		post_entry = vm_mapping(post_start_addr, post_length,
			orig_entry.perms_key, post_seg_size)
		print_debug(tag, ("new post_entry for vmatable: "
			"{0}").format(post_entry.to_str()))
	else:
		post_entry = None
		print_debug(tag, ("split_end_addr {0} matches or is beyond "
			"orig_end_addr {1} (extend={2}), so not adding a "
			"post_entry").format(hex(split_end_addr), hex(orig_end_addr),
			extend))

	new_entries = []
	updated_length = 0
	if pre_entry:
		new_entries.append(pre_entry)
		updated_length += pre_entry.length
	if mod_entry:
		new_entries.append(mod_entry)
		updated_length += mod_entry.length
	if post_entry:
		new_entries.append(post_entry)
		updated_length += post_entry.length
	
	# Sanity checks:
	if unmap:
		if updated_length != orig_entry.length - length:
			if not extend:
				print_error_exit(tag, ("after unmap, length of remaining "
					"regions is {0} bytes, but expect it to be {1}!").format(
					updated_length, orig_entry.length - length))
			elif updated_length != split_addr - orig_entry.start_addr:
				print_error_exit(tag, ("after unmap that \"extended\" "
					"an entry, length of regions is now {0} bytes, but "
					"expect it to be {1} bytes!").format(updated_length,
					split_addr - orig_entry.start_addr))
	else:
		if updated_length != orig_entry.length:
			if not extend:
				print_error_exit(tag, ("after non-extend re-protect, "
					"length of regions is {0} bytes, but expect it to "
					"still be original length {1}!").format(updated_length,
					orig_entry.length))
			elif updated_length != (orig_entry.length +
				(split_end_addr - orig_end_addr)):
				print_error_exit(tag, ("after re-protect that extended "
					"an entry, length of regions is now {0} bytes, but "
					"expect it to be {1} bytes!").format(updated_length,
					(orig_entry.length + (split_end_addr - orig_end_addr))))
	if len(new_entries) < 1 or len(new_entries) > 3:   # sanity check
		if unmap and extend:
			print_warning(tag, ("temporarily ignoring this warning"))  #TODO
		else:
			print_error_exit(tag, ("unexpected new_entries len: {0}").format(
				len(new_entries)))

	return new_entries

# Removes the vm_mapping that contains the specified address from the
# segment table. If starts_at is true, then the mapping will only be
# removed if it starts exactly at the specified address. The removed
# mapping is returned on success, or None is returned if a matching
# mapping could not be found.
def remove_vm_mapping(proc_info, search_addr, starts_at):
	# http://stackoverflow.com/a/682513/1230197
	tag = "remove_vm_mapping"

	return find_vm_mapping(proc_info, search_addr, starts_at, remove=True)

if __name__ == '__main__':
	print_error_exit("not an executable module")

