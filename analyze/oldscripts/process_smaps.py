#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from process_smaps_lib import *
from vm_regex import *
from pjh_utils import *
from vm_common import *
import datetime
import numpy as np
import os
import re
import shutil
import sys

#import matplotlib
#matplotlib.use('Agg')
#import matplotlib.pyplot as plt
#from matplotlib.backends.backend_pdf import PdfPages
#import matplotlib.mlab as mlab

# Globals:
debug_countdown       =     10
GENERATE_HISTOGRAMS   =   True
HIST_NUM_BINS         =    128  # should be a factor of HIST_MAX_PAGES...
HIST_MAX_PAGES        =   2048

##############################################################################
'''
Processes a proc_root/[pid]/smaps file and produces output that maps out
how sparse the address space is.
'''
def process_smaps_for_sparsity(proc_root, cmd, pid, output_dir,
		mean_dist_btw_maps, stddev_dist_btw_maps, iqr_dist_btw_maps):
	tag = "process_smaps_for_sparsity"
	global PAGE_SIZE_KB
	global PAGE_SIZE_BYTES

	smaps_fname = '{0}/{1}/{2}'.format(proc_root, pid, 'smaps')
	if not os.path.exists(smaps_fname):
		print_error_exit(tag, 'no smaps file ${0}'.format(smaps_fname))
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
	fname_prefix = "{0}/{1}".format(output_dir, "map_perms")
	perms_fname = "{0}_all".format(fname_prefix)
	perms____p_fname = "{0}_---p".format(fname_prefix)
	perms_r__p_fname = "{0}_r--p".format(fname_prefix)
	perms_r__s_fname = "{0}_r--s".format(fname_prefix)
	perms_rw_p_fname = "{0}_rw-p".format(fname_prefix)
	perms_rw_s_fname = "{0}_rw-s".format(fname_prefix)
	perms_rwxp_fname = "{0}_rwxp".format(fname_prefix)
	perms_r_xp_fname = "{0}_r-xp".format(fname_prefix)
	perms_f = open(perms_fname, 'w')
	perms____p_f = open(perms____p_fname, 'w')
	perms_r__p_f = open(perms_r__p_fname, 'w')
	perms_r__s_f = open(perms_r__s_fname, 'w')
	perms_rw_p_f = open(perms_rw_p_fname, 'w')
	perms_rw_s_f = open(perms_rw_s_fname, 'w')
	perms_rwxp_f = open(perms_rwxp_fname, 'w')
	perms_r_xp_f = open(perms_r_xp_fname, 'w')

	map_bottom_fname = '{0}/{1}'.format(output_dir, 'va-map-bottom')
	map_top_fname = '{0}/{1}'.format(output_dir, 'va-map-top')
	map_bottom_f = open(map_bottom_fname, 'w')
	map_top_f = open(map_top_fname, 'w')

	# Somewhere during the loop below, these will switch from bottom to top:
	map_f = map_bottom_f

	# Lists for scatter plots: 
	address_list = list()   # x-axis of scatter plot
	perms_list = list()     # y-axis of scatter plot

	#perms_f.write(("address\t---p\tr--p\tr--s\trw-p\trw-s\trwxp\tr-xp"
	#	"\tsegment\n"))
	perms_f.write(("address\t---p file\t---p anon\tr--p file\tr--p anon"
		"\tr--s file\tr--s anon\trw-p file\trw-p anon\trw-s file\trw-s anon"
		"\trwxp file\trwxp anon\tr-xp file\tr-xp anon\tsegment\n"))

	# To automatically calculate segments between memory mappings in the
	# address space, I initially tried setting segment boundaries between
	# mappings whose distance apart was greater than the mean distance apart
	# for all of the mappings in the address space, but this did not find
	# enough segments. Instead, multiply the standard deviation by a segment
	# "sensitivity" factor, and use this as the minimum distance between
	# mappings that defines a segment.
	begin_addr = -1
	end_addr = -1
	SEGMENT_SENSITIVITY = 10
	#segment_boundary_distance = stddev_dist_btw_maps * SEGMENT_SENSITIVITY
	segment_boundary_distance = iqr_dist_btw_maps
	#print(("APRIL: mean_dist_btw_maps={0}, stddev_dist_btw_maps={1}, "
	#	"iqr_dist_btw_maps={2}, segment_boundary_distance={2}").format(
	#		mean_dist_btw_maps, stddev_dist_btw_maps, iqr_dist_btw_maps,
	#		segment_boundary_distance))

	hit_heap = False
	switched_to_top = False
	line = smaps_f.readline()
	while line:
		# The first loops will not match either of these cases. Eventually,
		# we'll hit the [heap] lines in the map, and the first case will be
		# hit. Once we pass those lines, the second case will be hit exactly
		# once; then the remainder of the loops will not hit either case again.
		#   BUG: the [heap] region will end up in the "top" file of the
		#   output, right now...
		if heap_line.match(line):
			hit_heap = True
		elif hit_heap and not switched_to_top:
			map_f = map_top_f
			switched_to_top = True

		match = header_line.match(line)
		if header_line.match(line):
			match = header_line.match(line)
			(begin_s, end_s, perms, offset, dev, inode,
					name) = match.group(1,2,3,4,5,6,7)

			# If inode is equal to 0, then this mapping corresponds to either
			# [heap], [stack], [vdso], or an anonymous mapping (i.e. mmap).
			# Be sure to strip the name string of any trailing whitespace:
			name = (str(name)).strip()
			inode = int(inode)
			if inode == 0 and not name:  # why doesn't this work??
				anonymous = True
			else:
				anonymous = False

			# For a header line this:
			#   00400000-0041e000 r-xp 00000000 08:01 10491153  /usr/bin/...
			# Output something like this into the file perms_r_xp_f: one
			# line per allocated page:
			#   4194304 1
			#   4198400 1
			#   ...
			#   4313088 1
			prev_begin_addr = begin_addr    # remember previous mapping
			prev_end_addr = end_addr
			begin_addr = int(begin_s, 16)
			end_addr = int(end_s, 16)

			# If distance between this mapping and previous mapping
			# is greater than mean distance between mappings, label
			# this a segment boundary:
			distance = begin_addr - prev_end_addr
			if prev_begin_addr == -1 or distance >= segment_boundary_distance:
				perms_f.write(("{0}\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t15\n").format(begin_addr))
				address_list.append(int(begin_addr))
				perms_list.append(int(15))

			# Print out one line per PAGE:
			# Legend (these should probably be put into an "enum"...):
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
			max_perm_value = 15
			for addr in range(begin_addr, end_addr-1, PAGE_SIZE_BYTES):
				address_list.append(int(addr))
				if perms == "---p":
					if not anonymous:
						perms_f.write(("{0}"
							"\t1\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(1))
					else:
						perms_f.write(("{0}"
							"\t\t2\t\t\t\t\t\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(2))
					perms____p_f.write(("{0}\t1\n").format(addr))
				elif perms == "r--p":
					if not anonymous:
						perms_f.write(("{0}"
							"\t\t\t3\t\t\t\t\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(3))
					else:
						perms_f.write(("{0}"
							"\t\t\t\t4\t\t\t\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(4))
					perms_r__p_f.write(("{0}\t1\n").format(addr))
				elif perms == "r--s":
					if not anonymous:
						perms_f.write(("{0}"
							"\t\t\t\t\t5\t\t\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(5))
					else:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t6\t\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(6))
					perms_r__s_f.write(("{0}\t1\n").format(addr))
				elif perms == "rw-p":
					if not anonymous:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t7\t\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(7))
					else:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t8\t\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(8))
					perms_rw_p_f.write(("{0}\t1\n").format(addr))
				elif perms == "rw-s":
					if not anonymous:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t\t9\t\t\t\t\t\t\n").format(addr))
						perms_list.append(int(9))
					else:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t\t\t10\t\t\t\t\t\n").format(addr))
						perms_list.append(int(10))
					perms_rw_s_f.write(("{0}\t1\n").format(addr))
				elif perms == "rwxp":
					if not anonymous:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t\t\t\t11\t\t\t\t\n").format(addr))
						perms_list.append(int(11))
					else:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t\t\t\t\t12\t\t\t\n").format(addr))
						perms_list.append(int(12))
					perms_rwxp_f.write(("{0}\t1\n").format(addr))
				elif perms == "r-xp":
					if not anonymous:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t\t\t\t\t\t13\t\t\n").format(addr))
						perms_list.append(int(13))
					else:
						perms_f.write(("{0}"
							"\t\t\t\t\t\t\t\t\t\t\t\t\t\t14\t\n").format(addr))
						perms_list.append(int(14))
					perms_r_xp_f.write(("{0}\t1\n").format(addr))
				else:
					print_error_exit(tag, ("unexpected perms={0}").format(
						perms))

		line = smaps_f.readline()

	# One last segment boundary:
	perms_f.write(("{0}\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t15\n").format(end_addr))
	address_list.append(int(end_addr))
	perms_list.append(int(15))

	smaps_f.close()
	perms_f.close()
	perms____p_f.close()
	perms_r__p_f.close()
	perms_r__s_f.close()
	perms_rw_p_f.close()
	perms_rw_s_f.close()
	perms_rwxp_f.close()
	perms_r_xp_f.close()
	map_bottom_f.close()
	map_top_f.close()

	if True:
		# It looks like the x-axis for the scatter plot is represented
		# internally as a signed 64-bit integer; when given an address greater
		# than 2^63 - 1, plt.savefig() barfs up a "ValueError: math domain
		# error" exception. When I set a maximum value of 2^63 - 1 in the
		# address list, this error went away. So, for now, just truncate
		# anything greater than this value?
		#   Maybe makes more sense to divide entire x-axis by some amount
		#   in order to fit? Dividing by 2 might not be enough (the maximum
		#   address value would then still be 2^63, which is juuuust greater
		#   than 2^63 - 1), so divide by 4?
		scaled_addr_list = list()
		scale_factor = 4  # could also shift right by 4...
		for x in address_list:
#			#scaled_addr_list.append(int(x) % 2147483647)  # 2^31 - 1; works
#			#scaled_addr_list.append(int(x) % 4294967296)  # 2^32; works
#			#scaled_addr_list.append(int(x) % 2.8147498e+14)  # 2^48; works
#			#new_x = int(x) % 9.223372e+18  # 2^63 - 1; works...
#			new_x = int(x) % 10e+18  # fails!!
#			if x > 0x7fea68411000:
#				print(("x={0}\tnew_x={1}").format(x, new_x))
#			scaled_addr_list.append(new_x)  # 2^63 - 1; works
			new_x = int(x / scale_factor)
			scaled_addr_list.append(new_x)
		min_scaled_addr = scaled_addr_list[0]
		#max_scaled_addr = scaled_addr_list[-1]
		max_scaled_addr = int(2**64 / scale_factor)  #0xFFFF....F
		print("Generating scatter plot of address space for {0}".format(
			cmd))
		# See more notes about pyplot in process_smaps_for_contig()
		scale_factor = 2.0
		figsize = (8*scale_factor, 6*scale_factor)
		plt.figure(1, figsize=figsize)
		plot_fname = "{0}/{1}.png".format(output_dir, "mappings_scatter")
		plt.scatter(scaled_addr_list, perms_list)

		# Lots of different ways to scale the plot...
		#plt.axis([0, max_scaled_addr, 0, max_perm_value])
		#plt.axis([min_scaled_addr, max_scaled_addr, 0, max_perm_value])
		plt.axis([min_scaled_addr, 140644748165120/4, 0, max_perm_value])
		plt.xlabel("Address")
		plt.ylabel("Page permissions")
		plt.title("{0}: permissions of mapped virtual pages".format(cmd))
		#plots_pdf.savefig()
		plt.savefig(plot_fname)
		plt.close()
		  # don't forget, or next plot will be drawn on top of previous
		  # one! Ugh.
	
	return

'''
Processes a proc_root/[pid]/smaps file to find contiguous regions of VIRTUAL
memory that have been mapped independently.

TODO: add another characteristic to this function: find only contiguous
regions that have the same permissions mapping!

Additionally, keeps track of the distribution of mappings: the size of every
individual mapping is kept track of in a large array which can be used to
generate a histogram of mapping sizes, and a second array is used to keep
track of this distribution for the contiguous regions as well.
  (note: grepping for "^Size" in all of the smaps files appears to confirm
   that all mappings MUST be a multiple of 4 KB, as expected.)
'''
def process_smaps_for_contig(proc_root, cmd, pid, output_dir, plots_pdf,
		plots_contig_pdf,
		means_f, medians_f, mins_f, maxs_f, stddevs_f, means_contig_f,
		medians_contig_f, mins_contig_f, maxs_contig_f, stddevs_contig_f):
	tag = "process_smaps_for_contig"
	global PAGE_SIZE_KB
	global PAGE_SIZE_BYTES
	global HIST_NUM_BINS
	global HIST_MAX_PAGES

	contig_bottom_fname = '{0}/{1}'.format(
			output_dir, 'contiguous-ranges-bottom')
	contig_top_fname = '{0}/{1}'.format(output_dir, 'contiguous-ranges-top')
	smaps_fname = '{0}/{1}/{2}'.format(proc_root, pid, 'smaps')
	if not os.path.exists(smaps_fname):
		print_error_exit(tag, 'no smaps file ${0}'.format(smaps_fname))

	contig_bottom_f = open(contig_bottom_fname, 'w')
	contig_top_f = open(contig_top_fname, 'w')
	smaps_f = open(smaps_fname, 'r')

	# Somewhere during the loop below, these will switch from bottom to top:
	contig_f = contig_bottom_f

	# Build a list that holds the size of every mapping for this process.
	# Also keep track of various values for stats:
	mappings_list = list()  # in 4 KB pages!
	mappings_count = int(0)
	mappings_sum = int(0)  # in 4 KB pages!!
	mappings_list_contig = list()  # in 4 KB pages!
	mappings_list_contig_perms = list()  # in 4 KB pages!

	'''
	Set up arrays to use for histograms of distribution of mapping sizes:
	each element in the array represents a bin of HIST_GRANULARITY pages.
	We allocate bins for mappings up to HIST_MAX_PAGES; if we encounter
	any mapping sizes larger than this, they will all go into the final
	bin / element in the array. The index for a mapping that is some number
	of _pages_ x can be calculated simply as x / HIST_GRANULARITY (bin /
	element 0 will be unused if the granularity is 1); PAGE_SIZE_KB and
	PAGE_SIZE_BYTES can be used to convert sizes in other forms into a
	count of pages.
	  (I validated that this works, at least for HIST_GRANULARITY set to
	   1, 1000, and 100000.)
	
	Numpy documentation:
	  http://www.scipy.org/Tentative_NumPy_Tutorial
	  http://www.scipy.org/Numpy_Example_List
	'''
	'''
	HIST_GRANULARITY      =      1  # width of each "bin," in 4 KB pages
	num_bins = int((HIST_MAX_PAGES / HIST_GRANULARITY) + 2)
	hist_indiv = np.zeros(num_bins, int)  # allocate array of num_bins 0s
	max_bin = 0
	'''

	# Added to keep track of distances between mappings:
	begin_addr = -1
	end_addr = -1
	dist_btw_maps_sum = 0
	dist_btw_maps_count = 0
	dist_btw_maps_list = list()

	firstloop = True
	hit_heap = False
	switched_to_top = False
	contig_begin = ""
	contig_end = ""
	contig_count = 0
	contig_perms = ""
	contig_names = ""
	contig_perms_dups = 0
	contig_names_dups = 0
	line = smaps_f.readline()
	while line:
		# The first loops will not match either of these cases. Eventually,
		# we'll hit the [heap] lines in the map, and the first case will be
		# hit. Once we pass those lines, the second case will be hit exactly
		# once; then the remainder of the loops will not hit either case again.
		#   BUG: the [heap] region will end up in the "top" file of the
		#   output, right now...
		if heap_line.match(line):
			hit_heap = True
		elif hit_heap and not switched_to_top:
			contig_f = contig_top_f
			switched_to_top = True

		match = header_line.match(line)
		if match:
			(begin_s, end_s, perms, offset, dev, inode,
					name) = match.group(1,2,3,4,5,6,7)

			# Calculate size of mapping:
			prev_begin_addr = begin_addr  # save boundary for prev. mapping
			prev_end_addr = end_addr
			begin_addr = int(begin_s, 16)
			end_addr = int(end_s, 16)
			range_size = end_addr - begin_addr
			num_pages = int(range_size / PAGE_SIZE_BYTES)
			remainder = range_size % PAGE_SIZE_BYTES
			if remainder != 0:
				print_error_exit(tag, ("range_size={0} is not a multiple of "
					"{1}-byte page size!").format(range_size, PAGE_SIZE_BYTES))

			# Update running stats: ONLY if this is the first loop OR
			# contig_begin is set to something besides "" - when contig_begin
			# IS set to "", this loop should be ignored, because it's just
			# starting a new contiguous region. Ugh.
			if firstloop or contig_begin != "":
				mappings_list.append(num_pages)  # in 4 KB PAGES!
				mappings_count += 1
				mappings_sum += num_pages        # in 4 KB pages!
				if prev_begin_addr != -1:
					distance = begin_addr - prev_end_addr
					dist_btw_maps_sum += distance
					dist_btw_maps_count += 1
					dist_btw_maps_list.append(distance)

				'''
				# Use num_pages to increment individual histogram array:
				hist_idx = int(num_pages / HIST_GRANULARITY)
				if hist_idx >= num_bins:
					#print_error_exit(tag, ("invalid hist_idx={0}: num_bins is "
					#	"{1}!").format(hist_idx, num_bins))
					hist_idx = num_bins - 1
				hist_indiv[hist_idx] += 1
				if hist_idx > max_bin:
					max_bin = hist_idx
# DEBUG:				if hist_idx != 0:
#					print("num_pages={0}, using hist_idx={1}".format(num_pages,
#						hist_idx))
				'''

			firstloop = False

			# Now do contiguous mapping stuff:
			if contig_begin == "":  # start new contiguous region:
				contig_begin = begin_s
				contig_end = end_s
				contig_count = 1
				contig_perms = perms
				contig_names = name
				contig_perms_dups = 0
				contig_names_dups = 0
			else:
				if begin_s == contig_end:  # contiguous!
					contig_end = end_s
					contig_count += 1
					if perms not in contig_perms:
						contig_perms = contig_perms + " " + perms
					else:
						contig_perms_dups += 1
					if name not in contig_names:
						contig_names = contig_names + " " + name
					else:
						contig_names_dups += 1
				else:  # end previous contiguous range and begin new:
					c_begin = int(contig_begin, 16)
					c_end = int(contig_end, 16)
					c_range = c_end - c_begin
					c_pages = int(c_range / PAGE_SIZE_BYTES)
					remainder = c_range % PAGE_SIZE_BYTES
					if remainder != 0:
						print_error_exit("got remainder={0}".format(remainder))
					mappings_list_contig.append(c_pages)  # in 4 KB pages!

					# Write to contiguous mapping file:
					contig_f.write(
							("{0}-{1}\t({2} pages)\n").format(
								contig_begin, contig_end, c_pages))
					contig_f.write(
							("  subregions: {0}\n").format(contig_count))
					contig_f.write(
							("  permissions: {0} ({1} duplicates)\n").format(
								contig_perms, contig_perms_dups))
					contig_f.write(
							("  names: {0} ({1} duplicates)\n").format(
								contig_names, contig_names_dups))

					# begin new contiguous range by continuing, so this line
					# will be checked again!
					contig_begin = ""
					contig_end = ""
					contig_count = 0
					contig_perms = ""
					contig_names = ""
					contig_perms_dups = 0
					contig_names_dups = 0
					continue
			# end of "if match:"

		elif anon_hp_line.match(line):
			match = anon_hp_line.match(line)
			ahp_size = int(match.group(1))
			ahp_pages = int(ahp_size / PAGE_SIZE_KB)
#####			if ahp_size > 0:
#####				print_error_exit(tag, ("{0} kb ({1} pages) of anonymous "
#####					"huge pages!").format(ahp_size, ahp_pages))
		
		line = smaps_f.readline()

	smaps_f.close()
	contig_top_f.close()
	contig_bottom_f.close()

	# Calculate stats for this process:
	# http://docs.scipy.org/doc/numpy/reference/generated/numpy.generic.html
	mappings_list.sort()
	mappings_list_contig.sort()
	mappings_count_contig = len(mappings_list_contig)
	if len(mappings_list) != mappings_count:
		print_error_exit("mappings_list len={0}, but mappings_count "
				"is {1}!".format(len(mappings_list), mappings_count))
	mappings_array = np.array(mappings_list)
	mappings_array_contig = np.array(mappings_list_contig)
	mean = mappings_sum / mappings_count    # in 4 KB pages!
	mean_contig = mappings_sum / mappings_count_contig    # in 4 KB pages!
	if mappings_count % 2 == 0:  # (0, 1, 2, 3): count=4
		median = (mappings_list[int(mappings_count / 2) - 1] +
		          mappings_list[int(mappings_count / 2)]) / 2
	else:  # (0, 1, 2, 3, 4): count=5
		median = mappings_list[int(mappings_count / 2)]  # python truncates, right?
	if mappings_count_contig % 2 == 0:
		median_contig = (mappings_list_contig[int(mappings_count_contig / 2) - 1] +
		          mappings_list_contig[int(mappings_count_contig / 2)]) / 2
	else:
		median_contig = mappings_list_contig[int(mappings_count_contig / 2)]
	min_map = mappings_list[0]
	min_map_contig = mappings_list_contig[0]
	max_map = mappings_list[mappings_count - 1]
	max_map_contig = mappings_list_contig[mappings_count_contig - 1]
	stddev = np.std(mappings_array)
	stddev_contig = np.std(mappings_array_contig)
	means_f.write("{0:.2f}\t{1}\n".format(mean, cmd))
	medians_f.write("{0:.2f}\t{1}\n".format(median, cmd))
	mins_f.write("{0:.2f}\t{1}\n".format(min_map, cmd))
	maxs_f.write("{0:.2f}\t{1}\n".format(max_map, cmd))
	stddevs_f.write("{0:.2f}\t{1}\n".format(stddev, cmd))
	means_contig_f.write("{0:.2f}\t{1}\n".format(mean_contig, cmd))
	medians_contig_f.write("{0:.2f}\t{1}\n".format(median_contig, cmd))
	mins_contig_f.write("{0:.2f}\t{1}\n".format(min_map_contig, cmd))
	maxs_contig_f.write("{0:.2f}\t{1}\n".format(max_map_contig, cmd))
	stddevs_contig_f.write("{0:.2f}\t{1}\n".format(stddev_contig, cmd))

	# Distances between mappings: used to determine where the "segments"
	# are in this process.
	# http://docs.scipy.org/doc/numpy-dev/reference/generated/numpy.percentile.html
	#dist_btw_maps_list.sort()
	dist_btw_maps_array = np.array(dist_btw_maps_list)
	mean_dist_btw_maps = dist_btw_maps_sum / dist_btw_maps_count
	stddev_dist_btw_maps = np.std(dist_btw_maps_array)
	upper_percentile = np.percentile(dist_btw_maps_array, 99.9)
		# "A weighted average of the two nearest neighbors is used if the
		#  normalized ranking does not match q exactly."
	lower_percentile = np.percentile(dist_btw_maps_array, 00.00000001)
		# 0.0 doesn't work here for some reason
	iqr_dist_btw_maps = upper_percentile - lower_percentile
		# "inter-quartile range": for the firefox-2698 example smaps data,
		# a range from 00.00000001 to 99.9 results in an IQR of 88719043203.1,
		# which works to separate the two obvious visual segments at the end
		# of the address space

	if GENERATE_HISTOGRAMS:
		'''
		Generate histograms: np.histogram() will automatically generate
		histogram arrays from the original arrays of mappings. In order
		to make the plots more readable, I'd like to have some
		maximum mapping size (HIST_MAX_PAGES), and just include any mappings
		larger than that in the largest bin. np.histogram() just ignores
		values larger than the range you give it, however - so, pre-process
		the arrays to "truncate" mappings greater than HIST_MAX_PAGES down
		to that size exactly.
		http://docs.scipy.org/doc/numpy/reference/generated/numpy.histogram.html#numpy.histogram

		Actually, it turns out that we don't have to call np.histogram()
		before calling plt.hist() - however, histogram() could still be useful
		if we want to output the histogram frequency arrays to a file.
		'''
		mappings_array_trunc = mappings_array.copy()  # deep copy!!
		mappings_array_contig_trunc = mappings_array_contig.copy()
		for i in range(len(mappings_array_trunc)):
			if mappings_array_trunc[i] > HIST_MAX_PAGES:
				mappings_array_trunc[i] = HIST_MAX_PAGES
		for i in range(len(mappings_array_contig_trunc)):
			if mappings_array_contig_trunc[i] > HIST_MAX_PAGES:
				mappings_array_contig_trunc[i] = HIST_MAX_PAGES
		#hist, hist_edges = np.histogram(mappings_array_trunc,
		#	bins=HIST_NUM_BINS, range=(0, HIST_MAX_PAGES))
		#hist_contig, hist_edges_contig = np.histogram(mappings_array_contig_trunc,
		#	bins=HIST_NUM_BINS, range=(0, HIST_MAX_PAGES))

		'''
		Plot histograms: each bin is HIST_MAX_PAGES / HIST_NUM_BINS pages
		wide. IMPORTANT: the plt.hist() function does the same binning of
		data that the np.histogram() function does - this means that you
		should NOT pass the output of np.histogram as the first argument
		("x") to plt.hist(), but rather the same input that you passed to
		np.histogram(). We CAN use the "edges" output from np.histogram
		as input to plt.hist() to set the bin width.
		http://matplotlib.org/api/pyplot_api.html?highlight=hist#matplotlib.pyplot.hist
		  If bins is an integer, bins + 1 bin edges will be returned, consistent
		  with numpy.histogram() for numpy version >= 1.3...
		'''
		scale_factor = 2.0
		figsize = (8*scale_factor, 6*scale_factor)
		plt.figure(1, figsize=figsize)
		plot_fname = "{0}/{1}.png".format(output_dir, "mappings_hist")
		# This is known to work, but uses the hist_edges output from
		# np.histogram(), which we really don't need to calculate in
		# advance:
		#	n, bins, patches = plt.hist(mappings_array_trunc, bins=hist_edges,
		#			histtype='stepfilled', rwidth=0.8,
		#			color='green', facecolor='green')
		# This works just as well, and we don't have to calculate the
		# histogram frequencies in advance:
		n, bins, patches = plt.hist(mappings_array_trunc,
				bins=HIST_NUM_BINS, range=(0, HIST_MAX_PAGES),
				histtype='stepfilled', #rwidth=0.8,
				color='green', facecolor='green')
		plt.axis([0, HIST_MAX_PAGES, 0, np.amax(n)])
		plt.xlabel("Pages in mapping")
		plt.ylabel("Count (total mappings: {0})".format(mappings_count))
		plt.title("{0}: distribution of virtual memory mapping "
				"sizes".format(cmd))
		plots_pdf.savefig()
		plt.savefig(plot_fname)
		plt.close()
		  # don't forget, or next plot will be drawn on top of previous
		  # one! Ugh.
	
		plt.figure(1, figsize=figsize)  # Needed when making multiple plots
		plot_fname = "{0}/{1}.png".format(output_dir, "mappings_contig_hist")
		n, bins, patches = plt.hist(mappings_array_contig_trunc,
				bins=HIST_NUM_BINS, range=(0, HIST_MAX_PAGES),
				histtype='stepfilled', #rwidth=0.8,
				#histtype='bar', rwidth=0.8
				color='blue', facecolor='blue'
				)
		plt.axis([0, HIST_MAX_PAGES, 0, np.amax(n)])
		plt.xlabel("Pages in mapping")
		plt.ylabel("Count (total mappings: {0})".format(mappings_count_contig))
		plt.title("{0}: distribution of contiguous virtual memory mapping "
				"sizes".format(cmd))
		plots_contig_pdf.savefig()
		plt.savefig(plot_fname)
		plt.close()

	return (mean_dist_btw_maps, stddev_dist_btw_maps, iqr_dist_btw_maps)

'''
Scans through a /proc directory looking for /proc/[pid]/smaps files to
process.
'''
def process_proc_root(proc_root, output_dir):
	tag = 'process_proc_root'
	#print_debug(tag, 'entered')

	# References:
	#   http://docs.python.org/3/library/os.html#module-os
	#   http://docs.python.org/3/library/os.path.html#module-os.path
	#   http://docs.python.org/3/library/re.html

	# Set up global stats files:
	stats_files = ["stats_means", "stats_medians", "stats_mins", "stats_maxs",
			"stats_stddevs", "stats_means_contig", "stats_medians_contig",
			"stats_mins_contig", "stats_maxs_contig", "stats_stddevs_contig"]
	means_fname = "{0}/{1}.txt".format(output_dir, stats_files[0])
	medians_fname = "{0}/{1}.txt".format(output_dir, stats_files[1])
	mins_fname = "{0}/{1}.txt".format(output_dir, stats_files[2])
	maxs_fname = "{0}/{1}.txt".format(output_dir, stats_files[3])
	stddevs_fname = "{0}/{1}.txt".format(output_dir, stats_files[4])
	means_contig_fname = "{0}/{1}.txt".format(output_dir, stats_files[5])
	medians_contig_fname = "{0}/{1}.txt".format(output_dir, stats_files[6])
	mins_contig_fname = "{0}/{1}.txt".format(output_dir, stats_files[7])
	maxs_contig_fname = "{0}/{1}.txt".format(output_dir, stats_files[8])
	stddevs_contig_fname = "{0}/{1}.txt".format(output_dir, stats_files[9])
	means_f = open(means_fname, 'w')
	medians_f = open(medians_fname, 'w')
	mins_f = open(mins_fname, 'w')
	maxs_f = open(maxs_fname, 'w')
	stddevs_f = open(stddevs_fname, 'w')
	means_contig_f = open(means_contig_fname, 'w')
	medians_contig_f = open(medians_contig_fname, 'w')
	mins_contig_f = open(mins_contig_fname, 'w')
	maxs_contig_f = open(maxs_contig_fname, 'w')
	stddevs_contig_f = open(stddevs_contig_fname, 'w')
	means_f.write("Mean pages in mapping\tProcess\n")
	medians_f.write("Median pages in mapping\tProcess\n")
	mins_f.write("Min pages in mapping\tProcess\n")
	maxs_f.write("Max pages in mapping\tProcess\n")
	stddevs_f.write("Stddev pages in mapping\tProcess\n")
	means_contig_f.write("Mean pages in contiguous mapping\tProcess\n")
	medians_contig_f.write("Median pages in contiguous mapping\tProcess\n")
	mins_contig_f.write("Min pages in contiguous mapping\tProcess\n")
	maxs_contig_f.write("Max pages in contiguous mapping\tProcess\n")
	stddevs_contig_f.write("Stddev pages in contiguous mapping\tProcess\n")

	# Set up PDF document where multiple plots can be saved:
	# http://matplotlib.org/faq/howto_faq.html#save-multiple-plots-to-one-pdf-file
	#plots_pdf = PdfPages("{0}/{1}.pdf".format(output_dir, "VASpace-plots"))
	#plots_contig_pdf = PdfPages("{0}/{1}.pdf".format(output_dir, "mappings_contig"))
	plots_pdf = None
	plots_contig_pdf = None

	(ms_list, ms_dict) = create_memstat_objects()

	# Scan through all of the process subdirectories in the proc_root
	# directory, and analyze the directories named with just a PID
	# (corresponding to a process currently running on the system).
	if not os.path.exists(proc_root):
		print_error_exit(tag, 'proc_root directory \'{0}\' does not exist!'.format(proc_root))
	dir_contents = os.listdir(proc_root)

	for item in dir_contents:
		match = valid_pid_file.match(item)
		if match:
			pid = match.group(1)
			pid_dir = '{0}/{1}'.format(proc_root, pid)
			if os.path.isdir(pid_dir):
				process_pid_dir(pid_dir, pid, output_dir,
						ms_list, ms_dict,
						plots_pdf, plots_contig_pdf,
						means_f, medians_f, mins_f, maxs_f, stddevs_f,
						means_contig_f, medians_contig_f, mins_contig_f,
						maxs_contig_f, stddevs_contig_f)

	#plots_pdf.close()
	#plots_contig_pdf.close()
	means_f.close()
	medians_f.close()
	mins_f.close()
	maxs_f.close()
	stddevs_f.close()
	means_contig_f.close()
	medians_contig_f.close()
	mins_contig_f.close()
	maxs_contig_f.close()
	stddevs_contig_f.close()

	# Sort the stats files:
	for stat in stats_files:
		fname = "{0}/{1}".format(output_dir, stat)
		cmdline = 'cat {0}.txt | sort -nr > {0}_sorted.txt'.format(fname)
		exec_cmd_with_pipe(cmdline)

	return

def usage():
	print('usage: {0} <proc-root> <output-dir>'.format(sys.argv[0]))
	print('  proc-root: the output directory created by gather-smaps.py')
	print('  output-dir: directory to create and then write output to')
	sys.exit(1)

def parse_args(argv):
	tag = 'parse_args'

	if len(argv) != 3:
		usage()
	#print_debug(tag, 'argv: {0}'.format(argv))
	proc_root = argv[1]
	output_prefix = argv[2]
	return (proc_root, output_prefix)

def create_output_dir(output_prefix):
	tag = 'create_output_dir'
	#print_debug(tag, 'entered')

	#output_dir='{0}'.format(output_prefix)
	output_dir='{0}-{1}'.format(output_prefix,
			datetime.datetime.now().strftime("%Y%m%d-%H.%M.%S"))
	if os.path.exists(output_dir):
		print_error_exit(tag, 'Output directory \'{0}\' already exists'.format(
			output_dir))
	else:
		os.mkdir(output_dir)
	print('Output will be created in directory {0}'.format(output_dir))
	return output_dir

# Main:
if __name__ == '__main__':
	tag = 'main'
	#print_debug(tag, 'entered')

	# Numpy options: print entire array...
	np.set_printoptions(threshold=np.nan)

	# Set up input and output directories:
	(proc_root, output_prefix) = parse_args(sys.argv)
	#print_debug(tag, 'proc_root={0}, output_prefix={1}'.format(proc_root,
	#	output_prefix))
	if not os.path.exists(proc_root):
		print_error_exit(tag, 'input directory \'{0}\' does not exist!'.format(
			proc_root))
	output_dir = create_output_dir(output_prefix)
	#print_debug(tag, 'output_dir={0}'.format(output_dir))

	# Process the proc directory:
	process_proc_root(proc_root, output_dir)

	sys.exit(0)
else:
	print('Must run stand-alone')
	usage()
	sys.exit(1)

