# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from vm_regex import *
from pjh_utils import *
from vm_common import *
import itertools
import os
import re
import shutil

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
#import matplotlib.mlab as mlab

GENERATE_HBARS        =   True
GENERATE_SCATTER      =  False
GENERATE_SCATTER_DATA =  False  # huge scatterplot data output file
SCATTER_DICT = dict()   # UGH...
SCATTER_DICT["legend"] = ("address\t---p file\t---p anon"
	"\tr--p file\tr--p anon\tr--s file\tr--s anon\trw-p file"
	"\trw-p anon\trw-s file\trw-s anon\trwxp file\trwxp anon"
	"\tr-xp file\tr-xp anon\tsegment\n")

'''
Classes: http://docs.python.org/3/tutorial/classes.html
  ... For example, passing an object is cheap since only a pointer is passed
  by the implementation; and if a function modifies an object passed as an
  argument, the caller will see the change.
  
  Ugh this webpage is tiresome. You really call this a tutorial?

Class instantiation: create a new instance/object of MyClass and assign this
object to local variable x.
	x = MyClass()

Calling method functions: the call x.f() is exactly equivalent to MyClass.f(x).
'''

'''
Class for writing a particular type of data to a file...

	The /proc/[pid]/smaps files look like a series of entries, one for
	each region of virtual address space, with a header line followed
	by details about the pages contained in that region. For example:
	  00400000-00458000 r-xp 00000000 08:01 9968332  /usr/bin/screen
	  Size:                352 kB
	  Rss:                 312 kB
	  Pss:                 270 kB
	  Shared_Clean:         84 kB
	  Shared_Dirty:          0 kB
	  Private_Clean:       228 kB
	  Private_Dirty:         0 kB
	  Referenced:          312 kB
	  Anonymous:             0 kB
	  AnonHugePages:         0 kB
	  Swap:                  0 kB
	  KernelPageSize:        4 kB
	  MMUPageSize:           4 kB
	  Locked:                0 kB
'''
class MemStat:
	"""docstring for MemStat class goes here..."""
	global MEM_TYPES
	tag = "class MemStat"

	# Set just once, by constructor:
	name = ""
	perms = ""
	mem_type = ""
	process_fn = None
	start_fn = None
	finish_fn = None

	# Should be reset for each new process whose smaps file we process:
	output_dir = None
	plot_fname = None
	pdf_list = None
	output_f = None
	prog_name = None
	num_mappings = None
	min_addr = None
	max_addr = None
	processed_count = None
	prev_perms_key = None
	prev_begin_addr = None
	prev_end_addr = None
	contig_begin = None
	contig_end = None
	contig_region_list = None
	  # list of (begin_contig_addr, end_contig_addr) tuples
	mem_type_sums = None
	  # Stats counters for each category of memory in the smaps file: these
	  # may be updated by the process_fn and finish_fns, or they may be left
	  # untouched in some cases.
	  # Note: don't do something like "mem_type_sums = dict()" followed
	  # by initialization with keys+values here; for some reason this
	  # results in a single dict shared by all MemStat instances!
	perms_addrs = None
	  # Dictionary that maps each permission type (e.g. "r--xp") to a LIST
	  # of addresses of pages that have that permission. This list of addresses
	  # is the x-values for one series of scatterplot data.
	  # This dict may not be used by some MemStat objects.

	'''
	Every MemStat object may care about smaps entries with only a certain
	type of permissions and/or a certain type of memory. For example, a
	MemStat object initialized with perms = "r-xp" and mem_type =
	"AnonHugePages" will only keep track of data for memory in AnonHugePages
	in private code regions. If this MemStat object cares about mappings with
	any permissions or memory with any type, then the empty string "" should
	be passed for those arguments.
	The name argument is used for creating unique filenames, and should
	probably be the same as the name that is used for finding this object
	in the dictionary of MemStat objects.

	process_fn is a function that will be called when this MemStat object's
	process_smaps_entry() method is called. Its signature is:
		process_fn(self, smaps_entry) returns nothing

	start_fn and finish_fn pointers to functions that will be called (if
	not == None) when the MemStat's start() method is called at the beginning
	of the smaps file processing and when the MemStat's finish() method is
	called after the smaps file processing. The signatures for these functions
	are:
		start_fn(self) returns nothing
		finish_fn(self) returns nothing
	INVARIANT: after start_fn() and finish_fn() have been called, the MemStat
	object should be in the same state that it was before start_fn() was
	first called!! This will ensure that the MemStat object can be re-used
	for every different process' smaps file.
	'''
	def __init__(self, name, perms, mem_type, process_fn, start_fn, finish_fn):
		tag = "{0}.__init__".format(self.tag)
		if not name or perms is None or mem_type is None or process_fn is None:
			print_error_exit(tag, "empty argument to __init__")
		# Must use self.name, not just "name = new_name"!
		self.name = name
		self.perms = perms
		self.mem_type = mem_type
		self.process_fn = process_fn
		self.start_fn = start_fn
		self.finish_fn = finish_fn

		# Everything that's not set by an argument to the constructor should
		# be reset in this helper function:
		self.reset()
	
	def reset(self):
		# Set string and int variables to None; set object-type variables
		# (e.g. dicts and lists) to newly-constructed objects!
		self.output_dir = None
		self.plot_fname = None
		self.pdf_list = None
		self.output_f = None
		self.prog_name = None
		self.num_mappings = None
		self.min_addr = None
		self.max_addr = None
		self.processed_count = None
		self.prev_perms_key = None
		self.prev_begin_addr = None
		self.prev_end_addr = None
		self.contig_begin = None
		self.contig_end = None
		self.contig_region_list = list()
		self.mem_type_sums = dict()
		for mem_type in MEM_TYPES:
			self.mem_type_sums[mem_type] = 0
		self.perms_addrs = dict()
		for key in PERMS_KEYS:
			self.perms_addrs[key] = list()
	
	def to_str(self):
		return ("MemStat object: name={0}, perms={1}, mem_type={2}, "
				"output_dir={3}, output_f={4}, start_fn={5}, "
				"finish_fn={6}, process_fn={7}, prog_name={8}, "
				"plot_fname={9}").format(
				self.name, self.perms, self.mem_type, self.output_dir,
				self.output_f, self.start_fn, self.finish_fn,
				self.process_fn, self.prog_name, self.plot_fname)

	def mem_type_sums_to_str(self):
		lines = ["MemStat class for perms {0}:\n".format(self.perms)]
		for mem_type in MEM_TYPES:
			lines.append(("  {0}:\t{1} kB\n").format(mem_type,
				self.mem_type_sums[mem_type]))
		return "".join(lines)

	'''
	NOTE: all of the MEM_TYPES etc. keys must have already been inserted into
	the dictionary before calling this function.
	'''
	def mem_type_sums_reset(self):
		for (mem_type, mem_sum) in self.mem_type_sums.items():
			self.mem_type_sums[mem_type] = 0

	'''
	Internal helper function; not intended for external use!
	'''
	def construct_default_fname(self, suffix):
		return ("{0}/{1}.{2}").format(self.output_dir, self.name, suffix)
	
	'''
	Only works for some MemStat objects...
	'''
	def get_perms_key(self):
		return self.mem_type

	'''
	Sets the output directory for this process' use of the MemStat object,
	and calls the MemStat object's start_fn.
	Actually, all of these arguments have been made optional - they can be
	left as "" or None if appropriate. The start, process and finish()
	callback functions that are set for this MemStat object should know
	what to do with these args.
	'''
	def start(self, output_dir, prog_name, plot_fname, pdf_list):
		tag = "{0}.start".format(self.tag)

		self.reset()
		self.output_dir = output_dir
		if not output_dir:
			print_warning(tag, ("no output_dir set - is this "
				"expected?? name={0}").format(self.name))
		self.prog_name = prog_name
		self.plot_fname = plot_fname
		self.pdf_list = pdf_list
		self.processed_count = 0
		if self.start_fn:
			self.start_fn(self)

	def process_smaps_entry(self, smap_entry):
		tag = "{0}.process_smap_entry".format(self.tag)
		if not self.process_fn:
			print_error_exit(tag, "null process_fn")
		self.process_fn(self, smap_entry)
		self.processed_count += 1

	'''
	Calls the MemStat object's finish_fn and then clears its output
	directory. The MemStat object can't be used again until start() is
	called again to set a new output directory.
	'''
	def finish(self):
		tag = "{0}.finish".format(self.tag)
		if self.finish_fn:
			if self.processed_count > 0:
				self.finish_fn(self)
			else:
				# This happens occasionally when running chromium-browser:
				# an empty 004-smaps (or whatever iteration) file ends up
				# in the set of output files that we copied, but the file
				# is actually empty. In the ps_hierarchy file, these
				# processes appear to be "defunct" zombie processes.
				print_warning(tag, ("processed_count is {0}, so skipping "
					"call to self.finish_fn [{1}]!").format(
					self.processed_count, self.finish_fn))
		self.reset()

#################################################
# Function pointers passed to MapStats objects: #
#################################################
'''
'''
def perms_start(ms_self):
	tag = "{0}.perms_start".format(ms_self.tag)

	ms_self.mem_type_sums_reset()	
	ms_self.contig_address_list = list()
	ms_self.contig_begin = None
#	#ms_self.prev_addr = None

	ms_self.num_mappings = 0

	return

'''
Important: the size calculated in this function by parsing the "Size:  ... kB"
lines will differ from the size reported by the mapping's address boundaries
for the [stack] segment! For example:
	7fffdb79c000-7fffdb7d6000 rw-p 00000000 00:00 0                   [stack]
	Size:                236 kB
Subtracting 7fffdb7d6000 - 7fffdb79c000 = 3A000 -> 237568 bytes = 232 kB!!
So, the amount calculated here for the rw-pa mem_type will be 4 kB / 1 page
more than the amount if calculated using the mapping boundary addresses (e.g.
when computing segments) :-/
'''
def perms_process_smaps_entry(ms_self, smaps_entry_lines):
	global debug_countdown
	tag = "{0}.perms_dict_process".format(ms_self.tag)
	#print_debug(tag, "entered for ms_self.perms: {0}".format(ms_self.perms))

	firstline = True
	for line in smaps_entry_lines:
		if firstline:
			firstline = False
			header_match = HEADER_LINE.match(line)
			if not header_match:
				print_error_exit(tag, ("first line is not a header!"
					"\n\t{0}").format(line))
			(begin_s, end_s, perms, offset, dev, inode,
				name) = header_match.group(1,2,3,4,5,6,7)
			
			# Keep track of minimum and maximum addresses:
			begin_addr = int(begin_s, 16)
			end_addr = int(end_s, 16)
			if not ms_self.min_addr or begin_addr < ms_self.min_addr:
				ms_self.min_addr = begin_addr
			if not ms_self.max_addr or end_addr > ms_self.max_addr:
				ms_self.max_addr = end_addr
			ms_self.num_mappings += 1

			# Keep track of contiguous mappings for this permission type:
			if not ms_self.contig_begin:  # only the very first smaps entry!!
				ms_self.contig_begin = begin_addr
				ms_self.contig_end   = end_addr
			else:
				if begin_addr == ms_self.contig_end:  # continue contig region
					#print_debug(tag, ("{0}: contiguous mappings at "
					#	"address {1}").format(ms_self.name, begin_addr))
					ms_self.contig_end = end_addr  # move end of region
				else:  # end previous contig region, start new one
					ms_self.contig_region_list.append(
						(scale_addr(ms_self.contig_begin),
						 scale_addr(ms_self.contig_end)))
					ms_self.contig_begin = begin_addr
					ms_self.contig_end   = end_addr

		else:  # not a header line:
			#print_debug(tag, ("mem_line: {0}").format(line))
			mem_line_match = mem_type_line.match(line)
			if not mem_line_match:
				print_error_exit(tag, ("line {0} didn't match regex "
				"{1}").format(line, mem_type_line))
			(mem_type, size) = mem_line_match.group(1,2)
			size = int(size)
			#print_debug(tag, ("from mem_line got mem_type={0}, size = {1} "
			#	"kB").format(mem_type, size))

			# Dictionary lookup:
			#if DEBUG:
			#	if mem_type not in ms_self.mem_type_sums.keys():
			#		print_error_exit(tag, ("mem_type {0} not in "
			#			"mem_type_sums.keys {1}").format(mem_type,
			#			mem_type_sums.keys()))
			mem_type_sum = ms_self.mem_type_sums[mem_type]
			if mem_type_sum is None:
				print_error_exit(tag, ("mem_type_sums dict lookup failed "
					"for mem_type={0}").format(mem_type))
			#print_debug(tag, "sum so far: {0}: {1} kB".format(
			#	mem_type, mem_type_sum))
			mem_type_sum += size
			ms_self.mem_type_sums[mem_type] = mem_type_sum
			#print_debug(tag, "updated sum (size={0}): {1} kB".format(
			#	size, ms_self.mem_type_sums[mem_type]))

	#print_debug(tag, "smaps_entry_lines: {0}".format(smaps_entry_lines))
	#if DEBUG:
	#	for line in smaps_entry_lines:
	#		print("{0}".format(line))
	#print_debug(tag, "mem_type_sums dict after entire entry: {0}".format(
	#	ms_self.mem_type_sums_to_str()))
	#debug_countdown -= 1
	#if debug_countdown == 0:
	#	print_error_exit(tag, "exiting early")

	return

'''
Helper function...
'''
def seg_add(addr, seg_size_B):
	# Not sure if this is needed or not; when I add (2^64 - 1) to an
	# address like 0x7fea0dffd000, I still get a positive address
	# like 0x100007fea0dffcffe, beyond what I'd expect from 64 bits
	#     (0x0ffffffffffffffff).
	# I guess python handles integer addition beyond 64-bits automatically
	# :)
	if addr + seg_size_B < addr:  # overflow
		return addr_max
	return addr + seg_size_B

'''
Writes the contents of the mem_type_sums dictionary to the output file, then
closes it.
'''
def perms_finish(ms_self):
	tag = "{0}.perms_finish".format(ms_self.tag)

	# Don't have to open file until we get to here
	output_fname = ms_self.construct_default_fname("out")
	print_debug(tag, ("using output_fname {0}").format(output_fname))
	ms_self.output_f = open(output_fname, 'w')

	# Maintain same order as smaps file by iterating over ordered list
	# MEM_TYPES, rather than iterating over dict's items().
	for mem_type in MEM_TYPES:
		mem_sum = ms_self.mem_type_sums[mem_type]
		ms_self.output_f.write(("{0}\t{1}\n").format(mem_type, mem_sum))

	ms_self.output_f.close()
	ms_self.output_f = None

	# End the last contiguous address range:
	if ms_self.contig_begin:  # should always be non-None if at least one smaps
		ms_self.contig_region_list.append(
			(scale_addr(ms_self.contig_begin),
			 scale_addr(ms_self.contig_end)))

	if False:
		debug_str = list()
		for (b, e) in ms_self.contig_region_list:
			debug_str.append("[{0} {1}]".format(hex(b), hex(e)))
		debug_str = " ".join(debug_str)
		print_debug("", ("{0}: contiguous regions:\t{1}").format(
			ms_self.name, debug_str))
	
	# Write "segmentation" data to another file:
	fname = "segmentation"
	common = True
	if common:
		output_fname = ("{0}/{1}.tsv").format(ms_self.output_dir,
				fname)
		ms_self.output_f = open(output_fname, 'a')  # append!
	else:
		output_fname = ("{0}/{1}-{2}.tsv").format(ms_self.output_dir,
				ms_self.name, fname)
		ms_self.output_f = open(output_fname, 'w')

	# Iterate over list of contiguous regions and print out, for each fixed
	# segment size:
	#   perms type      - 
	#   segment size    - 
	#   mappings        - number of mappings
	#   mappings size   - total size of mappings
	#   pages           - number of pages to cover mappings
	#   segments        - number of segments to cover mappings
	#   segments size   - total size of segments
	#   fragmentation   - KB that become unused within segments
	#   fragmentation % - % of TOTAL SEGMENT SIZE that is now unused
	# Start with "variable" segment size: number of segments == number of
	# contiguous regions.
	mappings_size = ms_self.mem_type_sums["Size"]
	ms_self.output_f.write(("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t"
		"{7}\t{8}\n").format(
		ms_self.get_perms_key(), "Mappings","Mappings size (KB)",
		"Pages", "Segment size (KB)", "Segments", "Segments size (KB)",
		"Fragmentation (KB)", "Fragmentation (%)"))
	ms_self.output_f.write(("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t"
		"{7}\t{8}\n").format(ms_self.get_perms_key(),
		ms_self.num_mappings, mappings_size,
		int(mappings_size / PAGE_SIZE_KB), 0,  # 0 seg-size for variable width
		ms_self.num_mappings, mappings_size, 0, 0.0))

	addr_max = int(0xffffffffffffffff)  # 18446744073709551615
	KB = 1024
	MB = KB * KB
	GB = MB * KB
	TB = GB * KB
	segsizes = [
		# Exponentially increasing:
		#PAGE_SIZE_BYTES,
		#PAGE_SIZE_BYTES*2,
		#PAGE_SIZE_BYTES*4,
		#PAGE_SIZE_BYTES*8,
		#PAGE_SIZE_BYTES*16,
		#PAGE_SIZE_BYTES*32,
		#PAGE_SIZE_BYTES*64,
		#PAGE_SIZE_BYTES*128,
		#PAGE_SIZE_BYTES*256,
		#PAGE_SIZE_BYTES*512,
		#PAGE_SIZE_BYTES*1024,
		#PAGE_SIZE_BYTES*2048,
		#PAGE_SIZE_BYTES*4096,
		#PAGE_SIZE_BYTES*8192,

		# Arbitrary:
		1 * KB,
		16 * KB,
		128 * KB,
		1 * MB,
		16 * MB,
		128 * MB,
		1 * GB,
		16 * GB,
		128 * GB,

		addr_max  # single segment!
		]
	for seg_size_B in segsizes:
		#print_if_match(tag, ms_self.get_perms_key(), "rw-pf",
		#	("loop for seg_size_B={0} KB").format(seg_size_B))
		num_segs = 0
		seg_start = None
		seg_end = None
		for (begin, end) in ms_self.contig_region_list:
			#print_if_match(tag, ms_self.get_perms_key(), "rw-pf",
			#	("contig region: begin={0}, end={1} ({2} pages)").format(
			#	 hex(begin), hex(end), (end - begin) / PAGE_SIZE_BYTES))
			if not seg_start or begin > seg_end:
				# Region begins beyond end of current segment: end current
				# segment, start new segment at beginning of region.
				num_segs += 1
				seg_start = begin
				seg_end = seg_add(seg_start, seg_size_B - 1)
				#print_if_match(tag, ms_self.get_perms_key(), "rw-pf",
				#	("new seg for new region: start={0}, end={1}").format(
				#	 hex(seg_start), hex(seg_end)))
			while seg_end < end - 1:
				# Lay down more adjacent segments until end of current segment
				# reaches beyond end of current region:
				num_segs += 1
				seg_start = seg_add(0, seg_end + 1)
				seg_end = seg_add(seg_start, seg_size_B - 1)
				#print_if_match(tag, ms_self.get_perms_key(), "rw-pf",
				#	("new seg for continued region: start={0}, end={1}").format(
				#	 hex(seg_start), hex(seg_end)))
			# Loop again: seg_start and seg_end will remain to keep track of
			# the current segment. If the next (begin, end) contiguous region
			# is entirely within seg_start and seg_end, then none of the
			# conditions in the next loop will be hit. If the next (begin,
			# end) starts within the current segment but ends beyond it, then
			# the first condition will be skipped but the second (while loop)
			# will be hit. If the next (begin, end) starts outside of the
			# current segment, then the first condition will be hit, and the
			# second (while loop) condition may or may not be hit.
		total_segs_size_KB = int(num_segs * seg_size_B / 1024)
		fragmentation_KB = total_segs_size_KB - mappings_size
		if total_segs_size_KB > 0:
			frag_percent = fragmentation_KB / total_segs_size_KB
		else:
			frag_percent = 0.0
		ms_self.output_f.write(("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t"
			"{7}\t{8}\n").format(ms_self.get_perms_key(),
			ms_self.num_mappings,
			mappings_size, int(mappings_size / PAGE_SIZE_KB),
			int(seg_size_B / 1024), num_segs,
			total_segs_size_KB, fragmentation_KB, frag_percent))
		#abort_if_match(tag, ms_self.get_perms_key(), "rw-pf")

	ms_self.output_f.close()
	ms_self.output_f = None
	
	return

CONTIG = True  # temporary...

'''
Writes header information to file with permissions scatter plot:
'''
def perms_plotter_start(ms_self):
	global SCATTER_DICT
	global GENERATE_SCATTER_DATA
	tag = "{0}.perms_plotter_start".format(ms_self.tag)

	output_fname = ms_self.construct_default_fname("tsv")
	print_debug(tag, ("using output_fname {0}").format(output_fname))
	ms_self.output_f = open(output_fname, 'w')

	legend_line = SCATTER_DICT["legend"]
	if not legend_line:
		print_error_exit(tag, "got null legend from SCATTER_DICT")
	if GENERATE_SCATTER_DATA:
		ms_self.output_f.write(("{0}").format(legend_line))

	return

def perms_plotter_process_smaps_entry(ms_self, smaps_entry_lines):
	global SCATTER_DICT
	global GENERATE_SCATTER_DATA
	global debug_countdown
	tag = "{0}.perms_plotter_process".format(ms_self.tag)

	# For this case (constructing the scatterplot data), we only care
	# about the header line; we won't actually iterate through the rest
	# of the lines in the smaps entry.
	header_line = smaps_entry_lines[0]
	#print_debug(tag, "header_line: {0}".format(header_line))
	header_match = HEADER_LINE.match(header_line)
	if not header_match:
		print_error_exit(tag, ("first line is not a header!"
			"\n\t{0}").format(header_line))
	(begin_s, end_s, perms, offset, dev, inode, filename) = header_match.group(
			1,2,3,4,5,6,7)

	key = construct_perms_key(perms, inode, filename)
	perms_line = SCATTER_DICT[key]
	if not perms_line:
		print_error_exit(tag, ("got null perms_line for key={0}").format(key))

	# In addition to writing the scatterplot data to a TSV file, we'd also
	# like to keep the scatter data in-memory that that later we can use
	# it to generate a scatter plot. In order to do this, we'd like to keep
	# x-y data (address-permission) for every permission type; in other words,
	# for each permission type, we'd like to store a sorted list of addresses
	# of pages that are mapped with that permission type. The MemStat object's
	# perms_addrs dictionary is used for this:
	addr_list = ms_self.perms_addrs[key]

	begin_addr = int(begin_s, 16)
	end_addr = int(end_s, 16)
	if not ms_self.min_addr or begin_addr < ms_self.min_addr:
		ms_self.min_addr = begin_addr
	if not ms_self.max_addr or end_addr > ms_self.max_addr:
		ms_self.max_addr = end_addr

	# Check for contiguous mapping:
	if False: #CONTIG:
		if begin_addr == ms_self.prev_end_addr:
			print_debug("", ("adjacent mapping at boundary {0} [{1}]").format(
				ms_self.prev_end_addr, hex(ms_self.prev_end_addr)))
			#print_debug("", ("\t key={0}, prev_perms_key={1}").format(
			#	key[0:4], ms_self.prev_perms_key[0:4]))
			if key == ms_self.prev_perms_key:
				print_debug("", ("contiguous PERMISSION mapping at "
					"boundary {0} [{1}]").format(ms_self.prev_end_addr,
					hex(ms_self.prev_end_addr)))
			elif ms_self.prev_perms_key[0:4] == "---p":
				print_debug("", ("\tprevious mapping was a guard "
					"page!").format())
			elif key[0:4] == "---p":
				print_debug("", ("\tthis mapping is a guard page!").format())


	'''
	# If distance between this mapping and previous mapping
	# is greater than mean distance between mappings, label
	# this a segment boundary:
	if prev_begin_addr == -1 or distance >= segment_boundary_distance:
		perms_f.write(("{0}\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t15\n").format(begin_addr))
		address_list.append(int(begin_addr))
		perms_list.append(int(15))
	'''

	# Print out one line per PAGE:
	for addr in range(begin_addr, end_addr-1, PAGE_SIZE_BYTES):
		# Make sure that format of this line matches SCATTER_DICT["legend"]
		# in create_memstat_objects():
		scatter_line = ("{0}\t{1}").format(addr, perms_line)
		if GENERATE_SCATTER_DATA:
			ms_self.output_f.write(scatter_line)
		addr_list.append(addr)

	# Not sure if this is necessary or not...
	ms_self.perms_addrs[key] = addr_list

	# DEBUG:
	#print_debug(tag, ("address list for perms_addrs[{0}]: {1}").format(
	#	key, addr_list))
	#debug_countdown -= 1
	#if debug_countdown == 0:
	#	print_error_exit(tag, "abort")

#	# Remember old permissions and end-address, to check for contiguous
#	# regions:
#	ms_self.prev_perms_key = key
#	ms_self.prev_begin_addr = begin_addr
#	ms_self.prev_end_addr = end_addr

	return

'''
Writes footer information to file with permissions scatter plot...

Then constructs a scatter plot...
'''
def perms_plotter_finish(ms_self):
	global SCATTER_DICT
	tag = "{0}.perms_plotter_finish".format(ms_self.tag)

	# Write final segment boundary...
	segment_line = SCATTER_DICT["segment"]
	segment_line = ("{0}\t{1}").format(str(ms_self.max_addr),
			segment_line)
	if GENERATE_SCATTER_DATA:
		ms_self.output_f.write(("{0}").format(segment_line))
	
	if GENERATE_SCATTER:
		print_error_exit(tag, ("this code path was removed - see "
			"GENERATE_HBARS instead!").format())

	if GENERATE_HBARS:
		print_error_exit(tag, ("go back and refactor this method "
			"to simply call the code that was moved into "
			"simulate_segments_lib.py / process_info class "
			"(plot_vaspace())").format())
		if not ms_self.plot_fname and not ms_self.prog_name:
			print_error_exit(tag, ("Either ms_self.plot_fname={0} or "
				"prog_name={1} is not set! name={0}").format(
				ms_self.plot_fname, ms_self.prog_name, ms_self.name))
		if ms_self.plot_fname and ms_self.plot_fname != "":
			plot_fname = ms_self.plot_fname
				# should have been set at start() time
		else:  # some default...
			plot_fname = ("{0}/{1}-VASpace").format(ms_self.output_dir,
				ms_self.prog_name)
		print("Writing virtual address space plot at {0}".format(plot_fname))

		plot_scale_factor = 2.0
		figsize = (8*plot_scale_factor, 6*plot_scale_factor)
		bar_kwargs = {  # dictionary of plot attributes
			'visible' : True,
		}  #http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.scatter

		if ms_self.processed_count == 0:
			print_warning(tag, ("processed_count == 0, about to hit "
				"NoneType error below I think").format())
		max_perm_value = len(PERMS_KEYS) + 1  # plus one: for "segment" value
		unscaled_min = ms_self.min_addr
		unscaled_max = ms_self.max_addr
		scaled_min = scale_addr(ms_self.min_addr)
		scaled_max = scale_addr(ms_self.max_addr)
		#print_debug(tag, ("all plots: unscaled range [{0}, {1}], scaled "
		#	"range [{2}, {3}]").format(hex(unscaled_min), hex(unscaled_max),
		#	hex(scaled_min), hex(scaled_max)))

		# Loop and create multiple plots. It is impossible to plot the
		# process' entire virtual address space on one chart, because it
		# is way too wide.
		# Current strategy: plot everything, but only create plots that
		# are up to some number of GB wide.
		plot_count = 0
		max_plot_width = GB_BYTES * 1
		left_addr = unscaled_min
		while True:
			plt.figure(1, figsize=figsize)  # needed when making multiple plots

			# Goal: in this plot, only include regions that start beyond
			# left_addr and end before right_addr.
			right_addr = left_addr + max_plot_width - 1
			if right_addr > MAX_ADDR64:
				right_addr = MAX_ADDR64
			min_addr_this_plot = MAX_ADDR64
			max_addr_this_plot = 0x0
			start_next_plot = MAX_ADDR64
			#print_debug(tag, ("starting plotting loop for addr range up "
			#	"to [{0}, {1}] (width {2} GB); min_addr_this_plot = {3}, "
			#	"max_addr_this_plot = {4}").format(
			#	hex(left_addr), hex(right_addr),
			#	(right_addr - left_addr + 1) / GB_BYTES,
			#	hex(min_addr_this_plot), hex(max_addr_this_plot)))

			y_value = 1
			y_labels = [""] + PERMS_KEYS
			colors = itertools.cycle(['b', 'g', 'r', 'c', 'm', 'y'])#, 'k'])
			  # Re-start color cycle for every plot.
			  # http://matplotlib.org/examples/pylab_examples/filledmarker_demo.html
			  # http://matplotlib.org/api/colors_api.html
			for key in PERMS_KEYS:
				addr_list = ms_self.perms_addrs[key]
				if addr_list is None:
					print_error_exit(tag, ("no addr_list found in perms_addrs "
						"for key {0}").format(key))
				#if DEBUG:
				#	print_warning(tag, ("verifying that address list is "
				#		"sorted - disable this code eventually!").format())
				#	sl_verify_is_sorted(addr_list)
				#print_debug(tag, ("entire addr_list for key {0}: "
				#	"{1}").format(key, list(map(lambda x: hex(x), addr_list))))

				# Pre-process addr_list: in perms_plotter_process_smaps_entry(),
				# addr_list is constructed by adding one address for every
				# PAGE_SIZE_BYTES in the mapping. So, while the next address in
				# addr_list is PAGE_SIZE_BYTES beyond the previous address,
				# count it as one contiguous mapping.
				#   This is kind of reversing the work that was done in
				#   perms_plotter_process_smaps_entry(), but it will also
				#   coalesce
				#   mappings that were separate but contiguous in the original
				#   smaps.
				# It looks like the x-axis for the scatter plot is represented
				# internally as a signed 64-bit int; when given an address
				# greater than 2^63 - 1, plt.savefig() barfs up a
				# "ValueError: math domain error" exception. When I set
				# a maximum value of 2^63 - 1 in the
				# address list, this error went away. So, for now, just truncate
				# anything greater than this value?
				#   Maybe makes more sense to divide entire x-axis by some
				#   amount in order to fit? Dividing by 2 might not be
				#   enough (the maximum address value would then still be
				#   2^63, which is juuuust greater than 2^63 - 1), so divide
				#   by 4?
				contig_addr_list = list()
				contig_begin = None
				prev_addr = None
				sliced_addr_list = []
				if len(addr_list) > 0 and addr_list[-1] >= left_addr:
					# If last address in addr_list is less than left_addr,
					# just skip this - avoids ValueError thrown from
					# sl_index_ge().
					start_idx = sl_index_ge(addr_list, left_addr)
					sliced_addr_list = addr_list[start_idx:]
					#print_debug(tag, ("key {0}: starting from idx {1} in "
					#	"addr_list: {2}").format(key, start_idx,
					#	hex(sliced_addr_list[0])))
					#print_debug(tag, ("entire sliced_addr_list: {0}").format(
					#	list(map(lambda x:hex(x), sliced_addr_list))))
				for addr in sliced_addr_list:
					# Splitting up plots:
					if addr + PAGE_SIZE_BYTES - 1 > right_addr:
						if addr < start_next_plot:
							start_next_plot = addr
							#print_debug(tag, ("addr {0} + page size > "
							#	"right_addr {1}, so set start_next_plot to "
							#	"{2}").format(hex(addr), hex(right_addr),
							#	hex(start_next_plot)))
						break
					if addr < min_addr_this_plot:
						min_addr_this_plot = addr
						#print_debug(tag, ("set min_addr_this_plot = "
						#	"{0}").format(hex(min_addr_this_plot)))
					if addr + PAGE_SIZE_BYTES - 1 > max_addr_this_plot:
						max_addr_this_plot = addr + PAGE_SIZE_BYTES - 1
						#print_debug(tag, ("set max_addr_this_plot = "
						#	"{0} from addr {1}").format(
						#	hex(max_addr_this_plot), hex(addr)))

					# Track contiguous regions:
					if not prev_addr:
						# On first loop, we want to hit continue below
						prev_addr = addr - PAGE_SIZE_BYTES
					if not contig_begin:
						contig_begin = addr
					if addr == prev_addr + PAGE_SIZE_BYTES:
						#continue contig region
						prev_addr = addr
						continue
					else:  # start of new contig region
						contig_addr_list.append(
							[scale_addr(contig_begin),
							 scale_addr(prev_addr + PAGE_SIZE_BYTES)])
							  # Add PAGE_SIZE_BYTES so that rectangle will
							  # span the actual width of the mapping.
						contig_begin = addr
						prev_addr = addr
				if (len(sliced_addr_list) != 0 and
					contig_begin and prev_addr and
					contig_begin <= prev_addr):   # last one:
					contig_addr_list.append(
						[scale_addr(contig_begin),
						 scale_addr(prev_addr + PAGE_SIZE_BYTES)])

				bar_kwargs['gid'] = "{0} {1}".format(y_value, key)
				bar_kwargs['label'] = "{0} {1}".format(y_value, key)
				color = next(colors)

				# contig_addr_list is already scaled:
				for [l, r] in contig_addr_list:
					plt.barh(bottom=y_value, width=(r - l), height=0.5,
							left=l, color=color, linewidth=None,
							align='center', **bar_kwargs)
				y_value += 1
	
			# sanity checks for plot splitting:
			if (min_addr_this_plot == MAX_ADDR64 or
				max_addr_this_plot == 0x0):
				print_error_exit(tag, ("invalid min_addr_this_plot {0} or "
					"max_addr_this_plot {1}").format(hex(min_addr_this_plot),
					hex(max_addr_this_plot)))
			if (min_addr_this_plot < left_addr or
				max_addr_this_plot > right_addr):
				print_error_exit(tag, ("left-right range is [{0}, {1}], "
					"but addr_this_plot range is [{2}, {3}]").format(
					hex(left_addr), hex(right_addr),
					hex(min_addr_this_plot), hex(max_addr_this_plot)))

			plt.title("{0}: permissions of mapped virtual pages ({1} "
				"mappings)".format(ms_self.prog_name, "n"))
			print_warning(tag, "TODO: add mapping counter to MemStat; increment it in process() method!")

			scaled_min_this_plot = scale_addr(min_addr_this_plot)
			scaled_max_this_plot = scale_addr(max_addr_this_plot)
		
			# http://matplotlib.org/api/axis_api.html:
			# Bullshit: when width of plot [min_addr_this_plot,
			#   max_addr_this_plot] is just 1 page (4 KB), then pyplot
			#   apparently refuses to set the x-axis width correctly - the
			#   two ticks/labels overlap each other in the middle of the plot.
			#   I tried for an hour to fix this, but it's being ridiculous.
			ax = plt.axes()
			#ax.autoscale(False)
			#ax.autoscale(enable=True, axis='x', tight=True)
			#ax.autoscale(enable=False, axis='x', tight=True)

			label_kwargs = {
				'size' : 'x-large',   # x-large, xx-large also
			}

			xtick_ticks = [scaled_min_this_plot, scaled_max_this_plot]
			xtick_labels = [str(hex(min_addr_this_plot)),
				str(hex(max_addr_this_plot))]   # labels are unscaled!
			width = max_addr_this_plot - min_addr_this_plot + 1   # unscaled!
			#print_debug(tag, ("this loop: determined plot address range "
			#	"[{0}, {1}] (width {2} GB)").format(hex(min_addr_this_plot),
			#	hex(max_addr_this_plot), width/GB_BYTES))
			if width > max_plot_width:
				print_error_exit(tag, ("got width={0} bytes, but "
					"max_plot_width is {1} bytes!").format(width,
					max_plot_width))
			ax.set_xbound(scaled_min_this_plot, scaled_max_this_plot)
			ax.set_xlim(scaled_min_this_plot, scaled_max_this_plot)
			ax.set_xticks(xtick_ticks)
			ax.set_xticklabels(xtick_labels)
			ax.set_xlabel(("Address space - width {0} ({1} GB)").format(
				hex(width), width/GB_BYTES), **label_kwargs)

			ax.set_ybound(0, max_perm_value)
			ax.set_ylim(0, max_perm_value)
			ax.set_ylabel("Page permissions", **label_kwargs)
			#print_debug(tag, ("numpy range: [{0}]. normal range: "
			#	"[{1}]").format(list(np.arange(max_perm_value)),
			#	list(range(max_perm_value))))
			ax.set_yticks(range(max_perm_value))
			ax.set_yticklabels(y_labels)
			ax.tick_params(axis='both', labelsize='x-large')

			# Ugh
			#plt.tight_layout()
			#ax.autoscale(enable=True, axis='x', tight=True)
			#ax.autoscale(enable=False, axis='x', tight=True)

			# Save plot:
			full_plot_fname = ("{0}-{1}-{2}.{3}").format(
				plot_fname,
				str(plot_count).zfill(2),
				#hex(min_addr_this_plot),
				"0x" + (hex(min_addr_this_plot)[2:]).zfill(16),
				"png")
			#print_debug(tag, ("saving this plot at {0}").format(
			#	full_plot_fname))
			plt.savefig(full_plot_fname)
			for pdf in ms_self.pdf_list:
				pdf.savefig()
			plt.close()
				# Don't forget, or next plot will be drawn on top of previous
				# one!

			# Set up for next plot:
			plot_count += 1
			left_addr = start_next_plot
			if left_addr == MAX_ADDR64:
				#print_debug(tag, ("breaking out of plotting loop").format())
				break
			#print_debug(tag, ("looping again for next plot: "
			#	"left_addr={0}").format(hex(left_addr)))

	ms_self.output_f.close()
	ms_self.output_f = None

	return

'''
Builds an output line for a file containing tab-separated scatterplot data.
combo is the combination number to build a line for; num_combinations is the
total number of combinations that will be used. 0 <= combo < num_combinations;
the "value" of the scatterplot data for this combo will be combo + 1.
'''
def build_scatter_line(combo, num_combinations):
	tag = "build_scatter_line"
	if combo < 0 or combo >= num_combinations:
		print_error_exit(tag, "invalid combo={0}, num_combinations={1}".format(
			combo, num_combinations))

	line = []
	for i in range(combo):
		line.append("\t")
	line.append("{0}".format(combo + 1))
	for i in range(combo + 1, num_combinations):
		line.append("\t")
	line.append("\n")
	line = "".join(line)
	return line

'''
'''
def create_memstat_objects():
	global PERMS
	global MAP_TYPES
	global SCATTER_DICT
	tag = "create_memstat_objects"

	# Some MemStat objects will want to receive EVERY mapping from the
	# smaps file - for these objects, put them into a list that will be
	# iterated over for every mapping. Hopefully the size of this list is
	# not toooo large, for performance reasons...
	#
	# Other MemStat objects will only want to receive a mapping if it
	# matches a certain combination of PERMISSIONS and TYPE (file-backed
	# vs. anonymous). For these objects, put them into a dictionary, where
	# the key is constructed by appending the type ('f' vs. 'a') to the 
	# four permissions characters:
	#   ---p   r--p   r--s   rw-p   rw-s   rwxp   r-xp
	# Note that this procedure must also be followed in
	# process_smaps_unified(); if the key changes here, then it must change
	# there as well.
	ms_list = list()
	ms_dict = dict()

	# Set up list: each MemStat object corresponds to one output file.
	# One MemStat object for:
	#   Scatterplot style data (x-axis = address, y-axis = permission)
	#   ...
	#   map_bottom_ and map_top: separate mappings at top and bottom of
	#     address space?
	ms_list.append(MemStat("VASpace", "", "",
		perms_plotter_process_smaps_entry, perms_plotter_start,
		perms_plotter_finish))

#	print_error_exit(tag, "set up a C-struct-like structure for each "
#			"MemStats object?")
#		# http://docs.python.org/3.0/tutorial/classes.html#odds-and-ends

	# Set up dictionary of MemStat objects for each combination of permissions
	# and mapping type. In addition, set up another dict with the same keys,
	# but whose values are a string that should be written to a file that
	# will be used to generate a scatterplot of mapped pages.
	###SCATTER_DICT = dict()
	num_combinations = len(PERMS) * len(MAP_TYPES) + 1
		# add 1 for "segment" marker (no entry currently
	combo = 0
#	for perms in PERMS:
#		for map_type in MAP_TYPES:
#			key = "{0}{1}".format(perms, map_type)
	for key in PERMS_KEYS:
		ms_name = "perms_{0}".format(key)
		ms_dict[key] = MemStat(ms_name, perms, key,
				perms_process_smaps_entry, perms_start, perms_finish)

		# Build the line for the scatter file entry:
		scatter_line = build_scatter_line(combo, num_combinations)
		#print_debug(tag, "scatter_line={0}".format(scatter_line))
		SCATTER_DICT[key] = scatter_line
		combo += 1

	# Additional scatterplot lines that are not combinations of permissions
	# plus mapping types:
	###SCATTER_DICT["legend"] = ("address\t---p file\t---p anon"
	###	"\tr--p file\tr--p anon\tr--s file\tr--s anon\trw-p file"
	###	"\trw-p anon\trw-s file\trw-s anon\trwxp file\trwxp anon"
	###	"\tr-xp file\tr-xp anon\tsegment\n")
	assert combo == num_combinations - 1, "unexpected combo"
	segment_line = build_scatter_line(combo, num_combinations)
	#print_debug(tag, "segment_line={0}".format(segment_line))
	SCATTER_DICT["segment"] = segment_line

	# Legend / values that are expected (this was explicit in previous
	# version of this script):
	#  1: ---p file-backed
	#  2: ---p anonymous
	#  3: r--p file-backed
	#  4: r--p anonymous
	#  5: r--s file-backed
	#  6: r--s anonymous
	#  7: rw-p file-backed
	#  8: rw-p anonymous
	#  9: rw-s file-backed
	# 10: rw-s anonymous
	# 11: rwxp file-backed
	# 12: rwxp anonymous
	# 13: r-xp file-backed
	# 14: r-xp anonymous
	# 15: segment boundary
	# max_perm_value = 15

	#print_debug(tag, "SCATTER_DICT={0}".format(SCATTER_DICT))

	return (ms_list, ms_dict)

'''
Processes a proc_root/[pid]/smaps file and produces output that maps out
how sparse the address space is.
It is fine for ms_list or ms_dict to be None / empty here, they will just
not be used.
'''
def process_smaps_unified(smaps_fname, ms_list, ms_dict):
	tag = "process_smaps_unified"
	global PAGE_SIZE_KB
	global PAGE_SIZE_BYTES
	global HEADER_LINE

	smaps_f = open(smaps_fname, 'r')

	'''
	Possible permissions from smaps files:
	(grep -R permissions: * | cut -d ':' -f 3- | cut -d '(' -f 1 | sort | uniq)
	   ---p   r--p   r--s   rw-p   rw-s   rwxp   r-xp

	However, we'd additionally like to know which mappings are "anonymous"
	and which mappings are backed by files. Anonymous mappings can be made
	by the process using mmap() to get more free memory in the process' virtual
	address space, as an alternative to calling malloc() to get more space
	on the heap.
	'''

	# To automatically calculate segments between memory mappings in the
	# address space, I initially tried setting segment boundaries between
	# mappings whose distance apart was greater than the mean distance apart
	# for all of the mappings in the address space, but this did not find
	# enough segments. Instead, multiply the standard deviation by a segment
	# "sensitivity" factor, and use this as the minimum distance between
	# mappings that defines a segment.
	#SEGMENT_SENSITIVITY = 10
	##segment_boundary_distance = stddev_dist_btw_maps * SEGMENT_SENSITIVITY
	#segment_boundary_distance = iqr_dist_btw_maps
	#print(("APRIL: mean_dist_btw_maps={0}, stddev_dist_btw_maps={1}, "
	#	"iqr_dist_btw_maps={2}, segment_boundary_distance={2}").format(
	#		mean_dist_btw_maps, stddev_dist_btw_maps, iqr_dist_btw_maps,
	#		segment_boundary_distance))

	prev_begin_addr = -1
	begin_addr = 0
	smaps_entry_lines = []
	line = smaps_f.readline()
	while line:
		# Peek ahead:
		next_line = smaps_f.readline()

		header_match = HEADER_LINE.match(line)
		  # todo: replace HEADER_LINE with maps_line_re from
		  #   simulate_segments_lib.py ...
		if header_match or not next_line:
			# When we encounter a header line, or read the last line in the
			# smaps file, send the current smaps_entry off to the various
			# MapStats objects to be processed. Then use the new header line
			# as the beginning of the next smaps_entry.
			if len(smaps_entry_lines) != 0:  # skip on very first header line
				# Send the smaps_entry to every MapStats object in the list,
				# and the MapStats object in the dictionary that corresponds
				# to the key (permissions + mapping type):
				if ms_list:
					for ms in ms_list:
						ms.process_smaps_entry(smaps_entry_lines)
				if ms_dict:
					if ms_dict is not {}:
						ms = ms_dict[key]
						if not ms:
							print_error_exit(tag, ("no MemStats object found "
								"in dictionary for key {0}").format(key))
						ms.process_smaps_entry(smaps_entry_lines)

			# I've verified that the last entry in the smaps file is indeed
			# processed just above.
			if not next_line:
				break

			smaps_entry_lines = [line]
			(begin_s, end_s, perms, offset, dev, inode,
				name) = header_match.group(1,2,3,4,5,6,7)
			key = construct_perms_key(perms, inode, name)

			# Apparently sometimes when we read+copy the smaps file
			# (especially right after a process has started), we end
			# up with duplicate entries after the [stack] [vdso] [vsyscall]
			# entries at the end. This code ensures that the addresses in
			# the smaps file are monotonically increasing as we expect.
			begin_addr = int(begin_s, 16)
			if begin_addr <= prev_begin_addr:
				print_warning(tag, ("encountered begin_addr {0} <= "
					"prev_begin_addr {1} - means that smaps file {2} got "
					"corrupted during copy? Will stop processing this "
					"smaps file now.\n\tline: {3}").format(
					hex(begin_addr), hex(prev_begin_addr),
					smaps_fname, line))
				line = None
				break
			prev_begin_addr = begin_addr

		else:  # not a header line: continue previous smaps_entry
			# According to this web page, the most efficient way to construct
			# a string using a bunch of concatenations is to build up a list
			# first, then join the list together at the end.
			#    http://www.skymind.com/~ocrow/python_string/
			# See the second answer to this question also - a comment
			# explains why with immutable strings in python, this approach
			# makes sense:
			#    http://stackoverflow.com/questions/4435169/good-way-to-append-to-a-string
			smaps_entry_lines.append(line)

		line = next_line

	smaps_f.close()
	
	return

# Opens the specified smaps file, creates a "horizontal bars" chart that
# plots the virtual address space of the process, and writes the chart
# at ...
def smaps_file_to_vm_plot(output_dir, smaps_fname, prog_name, plot_fname,
	pdf_list):
	tag = "smaps_file_to_vm_plot"

	if not os.path.exists(output_dir):
		print_error_exit(tag, ("didn't find existing output_dir {0} as "
			"expected").format(output_dir))
	if not os.path.exists(smaps_fname):
		print_error_exit(tag, ("didn't find smaps_fname at {0} as "
			"expected").format(smaps_fname))
	#plot_fname += ".png"
	#if os.path.exists(plot_fname):
	#	print_warning(tag, ("plot_fname {0} already exists, will "
	#		"overwrite it").format(plot_fname))
	print_debug(tag, ("reading smaps file {0} and writing plot file at "
		"{1}.png; prog_name = {2}").format(smaps_fname, plot_fname,
		prog_name))

	# The scatterplot / horizontal-bars plot will be generated in the
	# output_dir.
	# Ignore ms_dict for now...
	(ms_list, ms_dict) = create_memstat_objects()
	for ms in ms_list:
		ms.start(output_dir, prog_name, plot_fname, pdf_list)
	
	process_smaps_unified(smaps_fname, ms_list, None)

	for ms in ms_list:
		ms.finish()

	return

'''
Processes a single "proc_root/[pid]" directory. This function assumes that
it is called only once on each pid directoy; it will create a corresponding
output directory in the output_root.
'''
def process_pid_dir(pid_dir, pid, output_root, ms_list, ms_dict,
		plots_pdf, plots_contig_pdf, means_f,
		medians_f, mins_f, maxs_f, stddevs_f, means_contig_f, medians_contig_f,
		mins_contig_f, maxs_contig_f, stddevs_contig_f):
	tag = "process_pid_dir"
	#print_debug(tag, "entered")

	# References:
	#   http://docs.python.org/3/library/re.html
	#   http://docs.python.org/release/3.2.3/library/functions.html#open
	#   http://stackoverflow.com/questions/10863617/python-remove-everything-after-a-space-with-hex-x00
	#   http://stackoverflow.com/questions/209513/convert-hex-string-to-int-in-python

	if not os.path.exists(pid_dir):
		print_error_exit(tag, 'pid_dir \'{0}\' does not exist!'.format(
			pid_dir))
	if not os.path.exists(output_root):
		print_error_exit(tag, 'output_root \'{0}\' does not exist!'.format(
			output_root))
	
	# Get process' name: if it has no name, then skip the rest of this
	# function (these processes have no maps / smaps files either;
	# /proc/[pid]/stack suggests that these are kernel worker threads).
	#   Note: I've later learned that the /proc/[pid]/comm file usually
	#   has a description of the thread, whether it's an application thread
	#   or a kernel worker thread (e.g. "khelper"). Could parse this file
	#   here too...
	cmdline_fname = '{0}/{1}'.format(pid_dir, 'cmdline')
	if not os.path.exists(cmdline_fname):
		print_error_exit(tag, 'no cmdline file ${0}'.format(cmdline_fname))
	cmdline_f = open(cmdline_fname, 'r')
	line = cmdline_f.readline()  # just one line
	cmdline_f.close()
	cmd = line.split('\x00')[0]  # null-bytes between arguments
	cmd = cmd.split(' ')[0]
	cmd = cmd.split('\r')[0]
	cmd = cmd.split('\n')[0]
	cmd = cmd.split('\0')[0]
	cmd = cmd.split(':')[0]      # e.g. 'sshd: pjh [priv]' -> 'sshd'
	cmd = cmd.split('/')[-1]     # e.g. '/sbin/init' -> 'init'
	if cmd == '':
		print_warning(tag, ("pid {0} has no command - probably a kernel "
			"worker thread").format(pid))
		return
	
	#output_dir = '{0}/{1}-{2}'.format(output_root, pid, cmd)
	output_dir = '{0}/{1}-{2}'.format(output_root, cmd, pid)
	#print_debug(tag, 'output_dir={0}'.format(output_dir))
	if os.path.exists(output_dir):
		print_error_exit(tag, 'output_dir \'{0}\' already exists!'.format(
			output_dir))
	os.mkdir('{0}'.format(output_dir))

	# Copy original files that we want to be placed in the processed
	# directory as well:
	smaps_fname = '{0}/{1}'.format(pid_dir, 'smaps')
	copy_fname = '{0}/{1}'.format(output_dir, 'smaps')
	if not os.path.exists(smaps_fname):
		print_error_exit(tag, 'no smaps file ${0}'.format(smaps_fname))
	shutil.copy(smaps_fname, copy_fname)
	
	pid_pdf = PdfPages("{0}/{1}.pdf".format(output_dir, "VASpace-plots"))
	pdf_list = [pid_pdf]

	for ms in ms_list:
		#plot_fname = "".format(output_dir, cmd, i)
		#ms.start(output_dir, cmd, plot_fname)
		ms.start(output_dir, cmd, "", pdf_list)
	for ms in ms_dict.values():
		ms.start(output_dir, cmd, "", [])
		#print_debug(tag, "ms.to_str(): {0}".format(ms.to_str()))

	process_smaps_unified(smaps_fname, ms_list, ms_dict)

	for ms in ms_list:
		ms.finish()
	for ms in ms_dict.values():
		ms.finish()

	pid_pdf.close()

#	(mean_dist_btw_maps, stddev_dist_btw_maps, iqr_dist_btw_maps) = process_smaps_for_contig(proc_root, cmd, pid,
#			output_dir, plots_pdf, plots_contig_pdf,
#			means_f, medians_f, mins_f, maxs_f, stddevs_f, means_contig_f,
#			medians_contig_f, mins_contig_f, maxs_contig_f, stddevs_contig_f)
#	process_smaps_for_sparsity(proc_root, cmd, pid, output_dir,
#			mean_dist_btw_maps, stddev_dist_btw_maps, iqr_dist_btw_maps)

	return


if __name__ == '__main__':
	print_error_exit("not an executable module")
