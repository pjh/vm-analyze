# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from trace.vm_regex import *
from util.pjh_utils import *
from analyze.process_group_class import *
from trace.vm_common import *
import itertools
import os
import re
import shutil
from collections import defaultdict

min_segment_size = 1   # must be a power of 2!!!

#############################################################################

def scale_addr(addr):
	#ADDR_SCALE_FACTOR =  1  # divide addrs to avoid signed int problems...
	ADDR_SCALE_FACTOR =  2  # divide addrs to avoid signed int problems...
	return int(addr / ADDR_SCALE_FACTOR)

# segset is a dictionary of segments: keys are segment sizes, values are
# tuples:
#   (num-segments, max-num-segments)
# plot_fname will have .png appended to it.
def segset_to_plot(segset, plot_fname, plot_title, pid_pdf):
	tag = "segset_to_plot"

	plot_fname = "{0}.png".format(plot_fname)
	print_debug(tag, "Writing segset plot to file {0}".format(plot_fname))
	scale_factor = 2.0
	figsize = (8*scale_factor, 6*scale_factor)
		# Default figsize is (8,6): leads to an 800x600 .png image
	plt.figure(num=1, figsize=figsize)
		# http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.figure

	bar_kwargs = {  # dictionary of plot attributes
		'visible' : True,
	}  #http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.scatter
	#label_kwargs = {
	#	'size' : 'large',   # x-large, xx-large
	#}

	seg_count = 0
	max_seg_count = 0
	width = 100.0
	if segset:
		xvals = sorted(segset.keys())
	else:
		xvals = []
	counts = []
	max_counts = []
	ymax = 0
	for x in xvals:
		(count, maxcount) = segset[x]
		counts.append(count)
		max_counts.append(maxcount)
		if max(count, maxcount) > ymax:
			ymax = max(count, maxcount)
		seg_count += count
		max_seg_count += maxcount
	#plt.title("{0}: segment sizes - up to {1} total segments".format(
	#	prog_name, max_seg_count))
	if 'sudo' in plot_title:   # HACK alert:
		plot_title = 'Cassandra'
	plt.title(plot_title, **title_kwargs)
	print_debug(tag, ("xvals: {0}").format(xvals))
	print_debug(tag, ("counts: {0}").format(counts))
	print_debug(tag, ("max_counts: {0}").format(max_counts))
	# Plot columns one at a time, in order to set column width
	# appropriately for log scale:
	width_factor = 10   # smaller factor = wider columns
	for i in range(0, len(xvals)):
		tick = xvals[i]
		count = counts[i]
		max_count = max_counts[i]
		bar_width = tick / width_factor   # right-er ticks have greater width
		
		plot_both_bars = False   # HACK!
		if plot_both_bars:
			#left = tick - (bar_width/2)
			left = tick - bar_width
			plt.bar([left], [count], width=bar_width, bottom=0,
				color="red", **bar_kwargs)
			plt.bar([left+bar_width], [max_count], width=bar_width, bottom=0,
				color="orange", **bar_kwargs)
		else:
			left = tick
			plt.bar([left], [count], width=bar_width, bottom=0,
				#color="red", **bar_kwargs)
				color='green', **bar_kwargs)

	xticks = []
	xlabels = []
	if len(xvals) == 0:
		xticks = [0, 1]
		xlabels = ["0 B", "1 B"]
	else:
		pow2 = 1
		#labels = itertools.cycle([1, 4, 16, 64, 256])
		while True:
			if pow2 < 1024:
				pow2 *= 4
				continue
			xticks.append(pow2)
			if pow2 < KB_BYTES:
				label = 'B'
				num = str(pow2)
			elif pow2 < MB_BYTES:
				label = 'KB'
				num = str(pow2 / KB_BYTES)
			elif pow2 < GB_BYTES:
				label = 'MB'
				num = str(pow2 / MB_BYTES)
			elif pow2 < TB_BYTES:
				label = 'GB'
				num = str(pow2 / GB_BYTES)
			else:
				label = 'TB'
				num = str(pow2 / TB_BYTES)
			xlabels.append(("{0} {1}").format(num, label))
			if pow2 >= xvals[-1]:
				break
			pow2 *= 4
	print_debug(tag, ("xticks: {0}").format(xticks))
	print_debug(tag, ("xlabels: {0}").format(xlabels))

	ax = plt.axes()
	ax.set_xscale("log")
	ax.set_xticks(xticks)
	ax.set_xticklabels(xlabels, rotation='vertical', **smallticklabel_kwargs)
	ax.set_xlabel(("Segment size").format(), **axislabel_kwargs)
	#ax.set_xlim(xticks[0], xticks[-1])
	ax.set_xlim(xticks[0] - xticks[0]/width_factor,
		xticks[-1] + xticks[-1]/width_factor)
	
	ax.set_ylabel("Count", **axislabel_kwargs)
	ax.set_ylim(0, ymax+10)

	ax.tick_params(axis='both', labelsize=plotconf['ticklabelsize'])

	# "shrink" the plot up, so that labels don't go off the bottom:
	box = ax.get_position()
	ax.set_position([box.x0, box.y0 * 1.4, box.width, box.height])

	# Save plot:
	if pid_pdf:
		pid_pdf.savefig()
	plt.savefig(plot_fname)
	plt.close()
		# Don't forget, or next plot will be drawn on top of previous
		# one!

	return

#############################################################################

# A processes_tracker is a container for multiple process_info objects.
class processes_tracker:
	"""docstring..."""
	tag = "class processes_tracker"

	# Members:
	proc_dict = None
	
	def __init__(self):
		tag = "{0}.__init__".format(self.tag)

		self.reset()
		return
	
	def reset(self):
		tag = "{0}.__init__".format(self.tag)

		self.proc_dict = dict()
		return

	def make_copy(self):
		tag = "{0}.copy".format(self.tag)

		new_proc_tracker = processes_tracker()
		new_proc_tracker.proc_dict = self.proc_dict.copy()
		return new_proc_tracker

	# Returns the process_info object for the specified pid.
	# Returns None if the pid is not found.
	def get_process_info(self, pid):
		tag = "{0}.get_process_info".format(self.tag)

		if pid is None:
			print_warning(tag, ("got None pid").format())
			return None

		try:
			proc_info = self.proc_dict[pid]
		except KeyError:
			return None

		if proc_info.get_pid() != pid:
			print_error_exit(tag, ("got process_info {0} from proc_dict, "
				"but its pid doesn't match lookup pid {1}").format(
				proc_info.to_str(), pid))

		return proc_info

	'''
	def set_process_info(self, pid, proc_info):
		tag = "{0}.set_process_info".format(self.tag)

		self.proc_dict[pid] = proc_info
		print_debug(tag, ("set proc_dict[{0}] = {1}").format(
			pid, proc_info.to_str()))
		return
	'''

	# Inserts proc_info into the dictionary of process_infos that are
	# being tracked. The pid of the process_info object is used as a
	# unique key for tracking processes. This method does not check if
	# a process_info object is already being tracked or not for the
	# specified proc_info.pid, so this method is also used to "update"
	# process_infos.
	def insert_process_info(self, proc_info):
		tag = "{0}.info_process_info".format(self.tag)

		self.proc_dict[proc_info.get_pid()] = proc_info
		print_debug(tag, ("set proc_dict[{0}] = {1}").format(
			proc_info.get_pid(), proc_info.to_str()))
		return

	# Returns a list of all of the process_info objects that are being
	# tracked, sorted by ascending pid.
	def get_all_process_infos(self):
		return sorted(self.proc_dict.values(),
			key=lambda proc_info: proc_info.get_pid())
	
	# Returns a list of all of the proc_infos for the tgids stored in
	# the parent's children field. On error, returns None.
	def get_child_process_infos(self, parent_tgid):
		l = []
		try:
			parent = self.proc_dict[parent_tgid]
			for child_tgid in parent.get_children_tgids():
				try:
					l.append(self.proc_dict[child_tgid])
				except KeyError:
					return None
		except KeyError:
			return None
		return l
	
	def get_all_root_process_infos(self):
		l = []
		for proc_info in self.proc_dict.values():
			if proc_info.get_is_rootproc():
				l.append(proc_info)
		return sorted(l, key=lambda proc_info: proc_info.get_pid())
	
	def num_tracked(self):
		return len(self.proc_dict)

	def write_process_maps(self, output_f):
		for proc_info in self.get_all_process_infos():
			proc_info.write_proc_map(output_f)
			output_f.write(("\n").format())

		return

#############################################################################
PROCESS_INFO_UNKNOWN_NAME = 'unknown'

class process_info:
	"""docstring for process_info class..."""
	tag = "class process_info"

	# Members: not all must/will be used
	progname = None
	speculative_progname = None
	pid = None
	ptgid = None   # parent's tgid
	children = None
	is_rootproc = None   # is this a "root" processes during the trace?
	tgid_for_stats = None   # tgid to "transfer" stats to
	context = None
		# "context" dict: things like
		#   brk: location of program break pointer
		#   open_fds: list of open file descriptors
		#   mmap_stats: (at-addr count, total mapped size)
		#     # todo: mmap_stats should be moved into stats dict...
	saw_fork = None
	saw_exec = None
	exec_follows_fork = None
	stats = None
	segset = None  # todo: make a "SegSet" class
	syscall_cmd = None
	syscall_args = None
	#vma_module_map = None
	#vma_fn_map = None
	vmatable = None   # only the vmas currently mapped into process
	all_vmas = None   # all vmas ever
	cp_vmas = None    # all_vmas since previous checkpoint reset
	use_bprm = False
	bprm_vma = None
	vma_hash_fn = None
	  # The plain "vmatable" keeps track of just the vmas that are currently
	  # present in the process' virtual memory mapping. all_vmas keeps
	  # track of *every* vma that was ever present in the process' memory
	  # map. all_vmas is a map - vma_hash_fn takes a vm_mapping as its
	  # argument and returns the key it should be hashed into all_vmas with.
	  # cp_vmas is like all_vmas, but it may be "reset" by checkpoints along
	  # the way as we analyze the trace.
	rq_counts = None   # "read-quantum"
	wq_counts = None   # "write-quantum"
	r_counts = None    # reads
	w_counts = None    # writes
	zero_quanta = None
	traced_by_pin = None

	# Use these to keep track of the points in time where this process
	# had the greatest number of allocated vmas and the greatest virtual
	# memory size:
	vma_count = None
	max_vma_count = None
	max_vma_count_time = None
	total_vm_size = None
	max_vm_size = None
	max_vm_size_time = None

	rss_pages = None

	# pid is required for construction; everything else may be set later.
	def __init__(self, pid):
		tag = "{0}.__init__".format(self.tag)

		# "tgid_for_stats" default to the pid used to initialize the
		# proc_info, but may be changed later.
		self.pid = pid
		self.tgid_for_stats = pid
		self.reset()

	def reset(self):
		tag = "{0}.reset".format(self.tag)

		# Call constructors for dict(), list(), etc. explicitly, to ensure
		# that every process_info has its own...
		self.progname = PROCESS_INFO_UNKNOWN_NAME
		self.speculative_progname = None
		self.context = dict()
		self.context["brk"] = int(0x0)
		self.context["open_fds"] = list()
		#self.context["mmap_stats"] = (0, 0)
		self.saw_fork = False
		self.saw_exec = False
		self.exec_follows_fork = False
		self.stats = dict()
		self.segset = None  # set later, by "strategy" code...
		self.syscall_cmd = None
		self.syscall_args = None
		self.vmatable = dict()
		self.all_vmas = dict()
		self.cp_vmas = dict()
		self.use_bprm = False
		self.bprm_vma = None
		#self.vma_module_map = dict()
		#self.vma_fn_map = dict()
		self.vma_hash_fn = None
		self.rq_counts = list()
		self.wq_counts = list()
		self.r_counts = list()
		self.w_counts = list()
		self.zero_quanta = 0
		self.traced_by_pin = False
		self.children = list()

		self.vma_count = 0
		self.max_vma_count = 0
		self.max_vma_count_time = -1
		self.total_vm_size = 0
		self.max_vm_size = 0
		self.max_vm_size_time = -1
		self.rss_pages = defaultdict(int)

		# Leave alone: pid, ptgid, is_rootproc, tgid_for_stats
		
		return

	# Resets proc_info data that is relevant to the ongoing simulation /
	# analysis. Sometimes we want to do a "full" reset that blows away
	# all of the previous virtual memory mappings that have been seen
	# (i.e. when the kernel emits a reset-sim event after a process exec).
	# Other times we only want to do a "checkpoint" reset that resets
	# cp_vmas and not much else.
	# Note that this function does NOT change the proc_info's context
	# dict!
	def reset_sim_data(self, cp_or_full):
		tag = "{0}.reset_sim_data".format(self.tag)

		# What simulation data is tracked in the proc_info struct that
		# we'd like to reset?
		#   stats, segset, vmatable, all_vmas, cp_vmas
		# What should stay the same?
		#   progname, pid, ptgid, is_rootproc, tgid_for_stats, children
		#   context? Should stay the same here, user may need to adjust though!
		#   syscall_cmd / args
		#   vma_hash_fn
		#   saw_fork and saw_exec

		# Things that will only be reset on a full reset:
		if cp_or_full == 'full':
			print_debug(tag, ("resetting stats dict that contains: "
				"{0}").format(stats_to_str(self.stats)))
			print_error_exit(tag, ("this is dead code, I think; "
				"if you need it, must review other things I've "
				"added to process_info objects, like the things "
				"adjusted in track_vm_size()").format())
			self.stats = dict()
			self.segset = None    # BUG: needs to be set to dict()?
			self.vmatable = dict()
			self.all_vmas = dict()
			self.use_bprm = False
			self.bprm_vma = None

			# I think this makes sense, but right now it doesn't really
			# matter: read / write events only come after the sim_reset
			# event anyway.
			self.end_sched_quantum()
			self.rq_counts = list()
			self.wq_counts = list()
			self.r_counts = list()
			self.w_counts = list()
			self.zero_quanta = 0
		
		elif cp_or_full != 'cp':
			print_error_exit(tag, ("invalid cp_or_full: {0}").format(
				cp_or_full))

		# Things that will always be reset, on either a full reset or
		# a checkpoint reset:
		self.cp_vmas = dict()
		# todo: eventually may want to add a separate stats dict for
		#   between-checkpoints...

		return

	def to_str(self):
		return ("process_info[progname={0}, pid={1}]").format(
			self.progname, self.pid)
	
	def get_progname(self):
		return self.progname

	def get_pid(self):
		return self.pid
	
	def name(self):
		return "{}-{}".format(self.progname, self.pid)
	
	def get_ptgid(self):
		return self.ptgid
	
	def get_children_tgids(self):
		return self.children
	
	def get_context(self):
		return self.context
	
	def get_stats(self):
		return self.stats
	
	def get_segset(self):
		return self.segset
	
	def get_syscall_cmd(self):
		return self.syscall_cmd
	
	def get_syscall_args(self):
		return self.syscall_args
	
	def get_vmatable(self):
		return self.vmatable

	# Returns a list of the vmas stored in the specified table. For the
	# all_vmas and cp_vmas tables, the lists of vmas stored for EACH
	# key will all be appended together. If the sort argument is True,
	# then these lists will be sorted by start-address (after they have
	# all been appended together).
	def get_vmalist(self, whichtable, sort):
		tag = "{}:get_vmalist".format(self.tag)

		vmas = []
		if whichtable == 'vmatable':
			vmas = self.vmatable.values()
		elif whichtable == 'all_vmas':
			for keylist in self.all_vmas.values():
				vmas += keylist   # list concatenate
		elif whichtable == 'cp_vmas':
			for keylist in self.cp_vmas.values():
				vmas += keylist   # list concatenate
		else:
			print_error_exit(tag, ("invalid whichtable {}").format(
				whichtable))

		if sort:
			return sorted(vmas, key=lambda vma: vma.start_addr)
		else:
			return vmas
	
	def get_tgid_for_stats(self):
		return self.tgid_for_stats
	
	def is_traced_by_pin(self):
		return self.traced_by_pin

	def is_progname_set(self):
		if ((not self.progname) or
			(self.progname == PROCESS_INFO_UNKNOWN_NAME) or
			(self.progname == '<...>')):
			return False
		return True

	def is_speculative_progname_set(self):
		return self.speculative_progname is not None
	
	def is_ptgid_set(self):
		return self.ptgid != None

	def get_is_rootproc(self):
		return self.is_rootproc
	
	def set_progname(self, progname):
		tag = "{}.set_progname".format(self.tag)

		self.progname = progname
		if (self.speculative_progname and
		    progname != self.speculative_progname):
			# It turns out that this can happen in the ridiculous
			# case explained in lookahead_fork_exec() where the
			# first thing that a forked process does is fork another
			# process. Ugh. However, in that case, we *set* the spec
			# progname, but never actually use it, because tgid_for_stats
			# works to get the correct plotting appname (tgid_for_stats
			# only doesn't work and the spec progname is used in other
			# weird cases where apache2 and chrome are forked from
			# other processes that we end up ignoring). Anyway,
			# don't perform strict check here;
			# if we actually do end up using the wrong speculative
			# progname for plotting, you'll realize it later.
			print_unexpected(False, tag, ("proc_info {}: speculative_"
				"progname was {}, but now setting progname to "
				"{}!").format(self.pid, self.speculative_progname,
				progname))
		return
	
	def set_speculative_progname(self, progname):
		self.speculative_progname = progname
	
	def set_pid(self, pid):
		self.pid = pid

	def set_ptgid(self, ptgid):
		self.ptgid = ptgid
	
	def set_is_rootproc(self, is_rootproc):
		self.is_rootproc = is_rootproc
	
	def set_tgid_for_stats(self, tgid_for_stats):
		self.tgid_for_stats = tgid_for_stats

	def set_segset(self, segset):
		self.segset = segset

	def set_syscall_cmd(self, syscall_cmd):
		self.syscall_cmd = syscall_cmd

	def set_syscall_args(self, syscall_args):
		self.syscall_args = syscall_args
	
	def add_to_stats(self, key, n):
		tag = "{0}.add_to_stats".format(self.tag)

		add_to_stats_dict(self.stats, key, n)
	
	def set_vma_hash_fn(self, fn):
		self.vma_hash_fn = fn
	
	def set_traced_by_pin(self):
		self.traced_by_pin = True

	def stats_to_str(self):
		return stats_to_str(self.stats)

	def context_to_str(self):
		return context_to_str(self.context)
	
	def segset_to_str(self):
		return segset_to_str(self.segset)

	def vmatable_to_str(self):
		return vmatable_to_str(self.vmatable)

	def segset_count(self):
		return segset_count(self.segset)

	def vmatable_count(self):
		return vmatable_count(self.vmatable)

	def set_saw_fork(self, yesno):
		self.saw_fork = yesno
		return

	def set_saw_exec(self, yesno):
		self.saw_exec = yesno
		return

	def set_exec_follows_fork(self, yesno):
		self.exec_follows_fork = yesno
		return

	# If we have seen either the fork ('dup_mmap' events) or the exec
	# ('__bprm_mm_init' event) for this proc_info, then we know that
	# we should have full information for it - it was started during
	# our trace (not before the trace started), and we should know
	# about all of its vmas.
	#   Actually, this isn't quite true - we could happen to start a
	#   trace just after a process' fork, but in time to see its exec,
	#   which will then start removing vmas from the address space
	#   that we don't actually know about. This happened in one trace
	#   so far...
	def have_full_info(self):
		return (self.saw_fork or self.saw_exec)

	def be_strict(self):
		# If we have full information about the process (we've seen either
		# its fork or its exec or both), then be strict about our checking
		# and assertions.
		return self.have_full_info()

	# Note that children tracked via this method are not necessarily
	# direct children of the process; they could be grandchildren /
	# grand-grandchildren / etc., but for measurement purposes we want
	# to group them with this top-level "root" process.
	def add_child(self, child_tgid):
		if not self.is_rootproc:
			print_error_exit(tag, ("adding a child {} to a proc_info {} "
				"that's not a rootproc - is this right?").format(
				child_tgid, self.name()))
		self.children.append(child_tgid)
		return

	# vma is a vm_mapping object. This function will add the vma to both
	# all_vmas and cp_vmas!
	def add_to_all_vmas(self, vma):
		tag = "{0}.add_to_all_vmas".format(self.tag)

		if not self.vma_hash_fn:
			print_error_exit(tag, ("self.vma_hash_fn is not defined").format())

		# Hash the vma and append it to the list of vmas with that hash value
		# in the all_vmas map.
		key = self.vma_hash_fn(vma)

		for d in [self.all_vmas, self.cp_vmas]:
			try:
				vmalist = d[key]
			except KeyError:
				vmalist = list()
				d[key] = vmalist
				  # I think this should work: only need to set the
				  # mapping once, then list itself is mutable (appending
				  # to it doesn't change its identity). This page says
				  # that lists are mutable:
				  #   http://docs.python.org/3/reference/datamodel.html
			vmalist.append(vma)

		return

	# internal helper function:
	def get_all_vma_list(self):
		# Construct a list of all vmas by appending together all of
		# the lists that are kept in the all_vmas dict:
		print_error_exit('get_all_vma_list', ("I think this method "
			"is deprecated - use get_vmalist() instead!").format())
		all_vma_list = []
		for vma_list in self.all_vmas.values():
			all_vma_list += vma_list
		return all_vma_list

	def get_cp_vma_list(self):
		# Construct a list of all vmas by appending together all of
		# the lists that are kept in the cp_vmas dict:
		print_error_exit('get_cp_vma_list', ("I think this method "
			"is deprecated - use get_vmalist() instead!").format())
		cp_vma_list = []
		for vma_list in self.cp_vmas.values():
			cp_vma_list += vma_list
		return cp_vma_list

	# Iterates over the entire all_vmas structure and calls the query_fn
	# on each vma. The query_fn should return a key (string or numeric)
	# when passed a vm_mapping object. query_all_vmas will return a new
	# mapping from these keys to the *list of* vmas that "satisfy" that key.
	# If the query_fn returns None, then the vma that was passed as an
	# argument will not be included anywhere in the returned mapping.
	# 
	# For example, a simple case would be a query_fn that examines vmas
	# and returns either "True" or "False" depending on whether or not
	# those vmas satisfy some condition; then, the caller can easily
	# get the list of vmas for which the condition is satisfied by:
	#   vmalist = proc_info.query_all_vmas(is_cond_true_fn)["True"]
	#
	# A query function that never returns None and always returned some
	# key will serve to "sort" or classify the vmas into lists for every
	# possible key. More sophisticated queries that return None for some
	# vmas can also be used to exclude vmas that do not meet some condition
	# while classifying the vmas by key at the same time.
	#
	# When writing query functions, be aware of how vmas are
	# created and unmapped, and what the stored vma_ops mean. For example,
	# note that a vma may be created by an 'alloc' or other vma_op, and
	# then unmapped when some other operation occurs and creates a new
	# vma with an op like 'resize' or 'access_change' to replace it. 
	def query_all_vmas(self, query_fn):
		tag = "{0}.query_all_vmas".format(self.tag)

		# SHORTCUT PATH: if query_fn == vma_hash_fn, then don't have to
		# iterate over all vmas, can just directly return the mapping that
		# we're already keeping track of. Make a copy first though, so
		# that the caller can't screw up our all_vmas dict.
		#   Well, with the change of query_fns to returning lists of keys
		#   rather than just a single key, it should no longer be possible
		#   for this to happen...
		if query_fn == self.vma_hash_fn:
			print_error_exit(tag, ("SHORTCUT PATH successfully hit!").format())
			return self.all_vmas.copy()

		#all_vma_list = self.get_all_vma_list()
		all_vma_list = self.get_vmalist('all_vmas', sort=False)
		return construct_dict_from_list(all_vma_list, query_fn)

	# See description of query_all_vmas above.
	def query_cp_vmas(self, query_fn):
		tag = "{0}.query_cp_vmas".format(self.tag)

		if query_fn == self.vma_hash_fn:
			print_error_exit(tag, ("SHORTCUT PATH successfully hit!").format())
			return self.cp_vmas.copy()

		cp_vma_list = self.get_cp_vma_list()		
		return construct_dict_from_list(cp_vma_list, query_fn)

	# See description of query_all_vmas above.
	def query_vmatable(self, query_fn):
		tag = "{0}.query_vmatable".format(self.tag)

		# Unlike all_vmas, the values in the vmatable are individual vmas,
		# not lists of vmas. So, we don't have much work to do here:
		return construct_dict_from_dict(self.vmatable, query_fn)

	def query_vmas(self, query_fn, whichtable):
		tag = "{0}.query_vmas".format(self.tag)

		if whichtable == 'vmatable':
			return self.query_vmatable(query_fn)

		elif whichtable == 'all_vmas':
			return self.query_all_vmas(query_fn)

		elif whichtable == 'cp_vmas':
			return self.query_cp_vmas(query_fn)

		else:
			print_error_exit(tag, ("invalid whichtable: "
				"{0}").format(whichtable))
		return (None, None)

	# Iterates over all of the vmas currently in the vmatable 
	#   What if a vma was removed from the vmatable and put into
	#   all_vmas during the previous quantum? Ugh - better iterate
	#   over all_vmas, I guess.
	def end_sched_quantum(self):
		tag = "end_sched_quantum"

		# Count the number of vmas that were written to and
		# read from in the previous quantum, as well as the total
		# number of read and write accesses.
		reads = 0
		writes = 0
		vmas_r = 0
		vmas_w = 0
		#for vma in self.get_all_vma_list():
		for vma in self.get_vmalist('all_vmas', sort=False):
			(rq, wq, r, w) = vma.reset_access()
			reads += rq
			writes += wq
			if rq > 0:
				vmas_r += 1
			if wq > 0:
				vmas_w += 1

		# Store the vma read and write counts for each quantum in a list,
		# so that we can calculate statistics and distributions and such
		# later. We want to do this even if the counts were 0 for this
		# quantum!
		# Note that numpy arrays are immutable (and thus inefficient for
		# repeated appending), so we use lists for storing the counts,
		# and may convert them to numpy arrays later.
		#
		# skip_zeros: when examining the vmas_r and vmas_w counts for
		# hello-world and firefox, there are some quanta where the
		# process is apparently scheduled in, but doesn't perform a
		# single read or write to a vma that we track. This seems
		# absolutely ridiculous - it must be a quirk of the sched_switch
		# events coming from the kernel (or unlikely but possibly there
		# are reads and writes that go to vmas that we are not tracking;
		# there are a handful of these in every trace, but they seem
		# fairly rare). So, if both the read and write vma counts are
		# zero, then we probably shouldn't bother appending them to
		# the lists that we're tracking, otherwise the statistics will
		# be skewed.
		skip_zeros = True
		if (vmas_r > 0 or vmas_w > 0) or (not skip_zeros):
			self.r_counts.append(reads)
			self.w_counts.append(writes)
			self.rq_counts.append(vmas_r)
			self.wq_counts.append(vmas_w)
			print_debug(tag, ("{0}-{1}: vmas read / written in this "
				"quantum: {2} / {3}").format(
				self.progname, self.pid, vmas_r, vmas_w))
			#print_debug(tag, ("quantum count arrays: {0} & {1}").format(
			#	self.rq_counts, self.wq_counts))
		else:
			#if reads > 0 or writes > 0:
			#	print_error_exit(tag, ("").format())
			self.zero_quanta += 1

		return

	def sched_stats_string(self):
		tag = "{0}.sched_stats_string".format(self.tag)
		
		if len(self.rq_counts) != len(self.wq_counts):
			print_error_exit(tag, ("inconsistent lengths: "
				"rq_counts {0}, wq_counts {1}").format(
				len(self.rq_counts), len(self.wq_counts)))
		quanta = len(self.rq_counts)
		#total_quanta = quanta + self.zero_quanta

		# Use numpy arrays.
		#   http://wiki.scipy.org/Tentative_NumPy_Tutorial#head-
		#   053463ac1c1df8d47f8723f470b62c4bd0d11f07
		r_array = np.array(self.r_counts)
		w_array = np.array(self.w_counts)
		rq_array = np.array(self.rq_counts)
		wq_array = np.array(self.wq_counts)
		#totals = rq_array + wq_array
		
		s = ("{0} scheduling quanta").format(quanta)
		if self.zero_quanta > 0:
			s += (" (ignored {0} quanta with no reads/writes)").format(
					self.zero_quanta)
		if quanta > 0:
			s += ("\nmean memory reads per quantum: {0:.2f} (std dev "
				"{1:.2f})\nmean memory writes per quantum: {2:.2f} "
				"(std dev {3:.2f})").format(
				r_array.mean(), r_array.std(),
				w_array.mean(), w_array.std())
			s += ("\nmean \"segments\" read per quantum: {0:.2f} (std dev "
				"{1:.2f})\nmean \"segments\" written per quantum: {2:.2f} "
				"(std dev {3:.2f})").format(
				rq_array.mean(), rq_array.std(),
				wq_array.mean(), wq_array.std())
			s += ("\nrq_array: {0}\nwq_array: {1}").format(
				self.rq_counts, self.wq_counts)

		return s

	# Writes the process' current memory map (vmtable) to the given
	# output file. The vmas will be sorted by ascending address, to
	# match the /proc/pid/maps file.
	def write_proc_map(self, output_f):
		tag = "{}.write_proc_map".format(self.tag)

		output_f.write(("{0}-{1}\n").format(self.progname, self.pid))
		#output_f.write(("{0}\n").format(self.sched_stats_string()))
		
		if self.bprm_vma != None:
			print_unexpected(False, tag, ("write_proc_map called while "
				"self.bprm_vma non-null: {}").format(self.bprm_vma.to_str()))

		# Sort by mapping's virtual address (i.e. matching maps file output):
		sorted_vmas = sorted(self.vmatable.values(),
			key=lambda vma: vma.start_addr)
		if len(sorted_vmas) > 0:
			for vma in sorted_vmas:
				#output_f.write(("{0}\n").format(vma.to_str_maps_format()))
				output_f.write(("{0}\n").format(vma.to_str_maps_plus()))
		else:
			output_f.write(("no vmas in vmatable\n").format())

		return

	# Creates a plot of the virtual address space for the current vmatable.
	# plot_fname will have .png added to it. If pdflist is non-empty, the
	# plots will be appended to the PDF files in the pdflist.
	def plot_vaspace(self, plot_fname, pdflist):
		tag = "plot_vaspace"

		# The process_info's vmatable contains individual vmas, keyed
		# by their start address. This is what we want for plotting, but
		# we want to sort the vmas by their permission first. The dict
		# that we construct here will have keys from PERMS_KEYS and values
		# that are *lists of vmas*.
		def query_fn(vma):
			return [vma.perms_key]
		table = 'vmatable'   # support all_vmas or cp_vmas later?
		(vmas_by_perm, vmacount) = query_vmas(self, query_fn, table)
		if vmacount == 0:
			print_warning(tag, ("vmacount in process {}-{}'s vmatable "
				"is 0; will not generate a VAspace plot, returning "
				"now").format(self.progname, self.pid))
			return
		proc_min_addr = self.get_min_addr(table)
		proc_max_addr = self.get_max_addr(table)

		plot_scale_factor = 2.0
		figsize = (8*plot_scale_factor, 6*plot_scale_factor)
		bar_kwargs = {  # dictionary of plot attributes
			'visible' : True,
		}  #http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.scatter

		max_perm_value = len(PERMS_KEYS) + 1  # plus one: for "segment" value
		unscaled_min = proc_min_addr
		unscaled_max = proc_max_addr
		scaled_min = scale_addr(proc_min_addr)
		scaled_max = scale_addr(proc_max_addr)
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

			y_value = 0
			y_labels = [""] + PERMS_KEYS
			colors = itertools.cycle(['b', 'g', 'r', 'c', 'm', 'y'])#, 'k'])
			  # Re-start color cycle for every plot.
			  # http://matplotlib.org/examples/pylab_examples/filledmark
			  # er_demo.html
			  # http://matplotlib.org/api/colors_api.html
			for perms_key in PERMS_KEYS:
				# Make sure to do these steps even in when we skip a
				# permission type:
				color = next(colors)
				y_value += 1  # start at height 1!

				try:
					vmalist = sorted(vmas_by_perm[perms_key],
						key=lambda vma: vma.start_addr)
				except KeyError:
					print_debug(tag, ("{}-{}: no vmas in list for perms key "
						"{} - continuing to next key").format(
						self.progname, self.pid, perms_key))
					continue
				#if DEBUG:
				#	print_warning(tag, ("verifying that address list is "
				#		"sorted - disable this code eventually!").format())
				#	sl_verify_is_sorted(addr_list)
				#print_debug(tag, ("entire addr_list for key {0}: "
				#	"{1}").format(perms_key, list(map(lambda x: hex(x), addr_list))))

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
					#	"addr_list: {2}").format(perms_key, start_idx,
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

#				bar_kwargs['gid'] = "{0} {1}".format(y_value, perms_key)
#				bar_kwargs['label'] = "{0} {1}".format(y_value, perms_key)
#
#				# contig_addr_list is already scaled:
#				for [l, r] in contig_addr_list:
#					plt.barh(bottom=y_value, width=(r - l), height=0.5,
#							left=l, color=color, linewidth=None,
#							align='center', **bar_kwargs)

# BOOKMARK: New code starts here: skip all of the addr_list crap above
# and just direcly plot each vma in vmalist that is within the
# left-addr, right-addr range!
				bar_kwargs['gid'] = "{0} {1}".format(y_value, perms_key)
				bar_kwargs['label'] = "{0} {1}".format(y_value, perms_key)

				# contig_addr_list is already scaled:
				for [l, r] in contig_addr_list:
					plt.barh(bottom=y_value, width=(r - l), height=0.5,
							left=l, color=color, linewidth=None,
							align='center', **bar_kwargs)

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

			plt.title("{}: permissions of mapped virtual pages ({} "
				"mappings)".format(self.progname, vmacount))

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
			for pdf in pdflist:
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

		return

	# Updates the rss (resident in physical memory) pages for this process.
	# pagetype must be one of RSS_TYPES (see vm_common.py). pagecount is
	# the *current* number of pages of this type (not the +/- change in
	# pagecount). Due to the way that the kernel tracks the rss page count,
	# pagecount can possibly be negative.
	# Returns: True on success, False on error.
	def set_rss_pages(self, pagetype, pagecount):
		tag = "{}.update_rss".format(self.tag)

		if pagetype not in RSS_TYPES:
			print_error(tag, ("invalid pagetype={}, not in RSS_TYPES="
				"{}").format(pagetype, RSS_TYPES))
			return False

		self.rss_pages[pagetype] = pagecount
		return True

	# Returns a reference to the dict that maps RSS_TYPES to page counts.
	# Note that some RSS_TYPES may not have been entered into the dict yet.
	def get_rss_pages(self):
		return self.rss_pages

#############################################################################
# Not part of process_info class:

# This method should be called every time a vma is added to or
# removed from the vmatable, OR when a vma is *resized* (see
# detailed comments in analyze_trace.py:map_unmap_vma()). This
# method not only tracks the total size of allocated virtual
# memory, but also the count of vmas, the maximum vma count and
# maximum vm size, and the timestamps when those maximums occurred.
# This tracking is ONLY done in the leader of the process group -
# if proc_info is not a root/leader process, then the size and count
# will be modified in for proc_info.tgid_for_stats!
#
# I verified that the tracking done here (max vm size and timestamp)
# matches the tracking done by the vmacount plots and vm_size plot.
# 
# Returns: nothing.
def track_vm_size(proc_info, proc_tracker, add_or_sub, size, timestamp):
	tag = "track_vm_size"

	if proc_info.is_rootproc:
		p = proc_info
		if proc_info.pid != proc_info.tgid_for_stats:
			# I suppose this will fail if/when group_multiproc is
			# False in the analysis script, but I rarely/never disable
			# that...
			print_error(tag, ("assert failed: is_rootproc True, but "
				"pid {} != tgid_for_stats {}").format(proc_info.pid,
				proc_info.tgid_for_stats))
	else:
		p = proc_tracker.get_process_info(proc_info.tgid_for_stats)
		if not p:
			print_unexpected(True, tag, ("get_process_info({}) "
				"failed").format(proc_info.tgid_for_stats))
			return
		if proc_info.pid == proc_info.tgid_for_stats:
			# I suppose this will fail if/when group_multiproc is
			# False in the analysis script, but I rarely/never disable
			# that...
			print_error(tag, ("assert failed: is_rootproc False, but "
				"pid {} == tgid_for_stats {}").format(proc_info.pid,
				proc_info.tgid_for_stats))

	if add_or_sub is 'add':
		p.vma_count += 1
		p.total_vm_size += size
		if p.vma_count > p.max_vma_count:
			p.max_vma_count = p.vma_count
			p.max_vma_count_time = timestamp
			print_debug(tag, ("vmacount_datafn: new max_vma_count "
				"{} (time {})").format(p.vma_count, timestamp))
		if p.total_vm_size > p.max_vm_size:
			p.max_vm_size = p.total_vm_size
			p.max_vm_size_time = timestamp
			print_debug(tag, ("vmacount_datafn: new max_vm_size "
				"{} (time {})").format(p.total_vm_size, timestamp))
	elif add_or_sub is 'sub':
		p.vma_count -= 1
		p.total_vm_size -= size
		if p.have_full_info():
			if p.vma_count < 0:
				print_unexpected(True, tag, ("{}: vma_count fell "
					"below 0 to {}!").format(p.name(),
					p.vma_count))
			if p.total_vm_size < 0:
				print_unexpected(True, tag, ("{}: total_vm_size "
					"fell below 0 to {}!").format(p.name(),
					p.total_vm_size))
	else:
		print_error(tag, ("invalid arg {}").format(add_or_sub))

	# After adding code to ignore vmas for shared libs and guard
	# regions, I verified that the tracking done here matches the
	# tracking done in the counts and sizes datafns. I also manually
	# validated that the counts when vmas are ignored match the
	# maps files at teh max-vma-count timestamp.
	debug_count(tag, ("{}").format(p.vma_count))
	debug_vmsize(tag, ("{} ({})").format(p.total_vm_size,
		pretty_bytes(p.total_vm_size)))

	return

# Examines the all_vmas tables of all of the proc_infos in the proc_group
# list and returns a list of all vmas that were active at the specified
# timestamp.
# Returns: a list of vmas, or None on error.
def get_active_vmas(proc_group, timestamp, call_ignore_vmas=False):
	tag = 'get_active_vmas'

	# Unfortunately, all of the query_fn infrastructure that I already
	# have set up won't quite work here, because the query_fns don't
	# take any arguments, and I need to pass the timestamp as a
	# variable...
	#   Actually, wait a minute: can I use a "closure" to get around
	#   this limitation?
	#     http://stackoverflow.com/a/2009645/1230197
	#     A decent "how-to" for closures is really hard to find...
	#   This actually works! Validated on max vma count and max VM size
	#   for dedup and Chrome... amazing.
	def point_in_time_queryfn(vma):
		tag = 'point_in_time_queryfn'
		nonlocal timestamp
		nonlocal call_ignore_vmas

		# A vma is active at a particular time if the initial timestamp
		# when it was mapped is <= the time AND the time when it was
		# unmapped is > the time. Note that just checking vma.is_unmapped
		# won't work, because when we're looking back in time when this
		# method is called, most/all of the vmas will have been unmapped
		# at some point already!
		if vma.timestamp <= timestamp:
			if ((not vma.is_unmapped or vma.unmap_timestamp > timestamp)
				and not (call_ignore_vmas and ignore_vma(vma))):
				#print_debug(tag, ("active: {}").format(vma))
				return ['active']
		#print_debug(tag, ("inactive: {}").format(vma))
		return None

	(vmadict, numvmas) = query_vmas_grouped(proc_group,
			point_in_time_queryfn, 'all_vmas')
	#print_debug(tag, ("vmadict keys={}; numvmas={}").format(
	#	vmadict.keys(), numvmas))
	if len(vmadict) > 1:
		print_unexpected(True, tag, ("vmadict has more than one key-value "
			"pair: {}").format(vmadict.keys()))
	try:
		vmalist = vmadict['active']
		if len(vmalist) != numvmas:
			print_unexpected(True, tag, ("assert failed: len(vmalist) "
				"= {}, but numvmas={}").format(len(vmalist), numvmas))
	except KeyError:
		if len(vmadict) != 0:
			print_unexpected(True, tag, ("vmadict has exactly "
				"one key-value pair, but key is not 'active', it's "
				"{}").format(vmadict.keys()))
		print_debug(tag, ("no active vmas apparently, returning "
			"empty vmalist").format())
		vmalist = []

	return vmalist

# Takes a list of active_vmas and removes vmas that are "identical",
# having the same:
#   start_addr
#   length
#   perms_key
#
# This results in a list of active vmas that only includes those that
# are "fundamental" to the application's execution (e.g. they would not
# disappear if the app were rewritten as multi-threaded instead of
# multi-process). The vmas that are eliminated are those for which
# copy-on-write will NEVER be performed!
#
# Returns a new list containing just distinct vmas.
def deduplicate_active_vmas(active_vmas):
	tag = 'deduplicate_active_vmas'

	def vmas_are_equal(one, other):
		# Be sure to check file / filename: I found an instance (from
		# chrome) where vmas matched on start_addr, length, and perms_key,
		# but had different filenames:
		# /var/cache/fontconfig/845c20fd2c4814bcec78e05d37a63ccc-le64.cache-3
		# /var/cache/fontconfig/9eae20f1ff8cc0a7d125749e875856bd-le64.cache-3
		# Also, don't try to check is_unmapped, since it represents whether
		# or not the vmas was unmapped at some point in the future, and may
		# not have any bearing on this moment when active_vmas is being
		# processed.
		if (one.start_addr == other.start_addr and
			one.length == other.length and
			one.perms_key == other.perms_key and
			one.filename == other.filename and
			one.offset == other.offset):
			#if False:   # debugging / sanity checking...
			#	# We expect timestamp to differ; vma_op and unmap_op
			#	# will likely differ as well, right? Yes. is_unmapped
			#	# may be True or False, but shouldn't differ.
			#	if (#one.filename != other.filename or
			#		#one.timestamp != other.timestamp or
			#		#one.vma_op != other.vma_op or
			#		#one.unmap_op != other.unmap_op
			#		#one.is_unmapped != other.is_unmapped
			#		):
			#		print_unexpected(True, 'vmas_are_equal',
			#			("two vmas match on start_addr, length, and "
			#				"perms_key, but not on other fields: "
			#				"[{} {}] [{} {}]").format(
			#				one.to_str_maps_format(), one,
			#				other.to_str_maps_format(), other))
			return True
		return False

	dedup_vmas = list()

	sorted_vmas = list(sorted(active_vmas, key=lambda vma: vma.start_addr))
	prev = None
	i = 0
	while i < len(sorted_vmas):
		# To be very safe: first make a list of all of the vmas with the
		# same start_addr
		startlist = [sorted_vmas[i]]
		i += 1
		while (i < len(sorted_vmas) and
				sorted_vmas[i].start_addr == startlist[0].start_addr):
			startlist.append(sorted_vmas[i])
			i += 1
		#print_debug(tag, ("initial startlist: {}").format(startlist))
		#orig_len = len(startlist)
	
		# Now, iterate over that list, and disregard any vmas that are
		# equivalent according to is_equal(). For the utmost safety /
		# completeness, we do an n^2 all-pairs check here:
		j = 0
		while j < len(startlist):
			left = startlist[j]
			k = j + 1
			while k < len(startlist):
				right = startlist[k]
				# IMPORTANT: only disregard vmas that are non-writeable!
				# If they are writeable, then copy-on-write *could* be
				# performed (perhaps not likely, but...), so these vmas
				# should be kept + counted.
				if ((not right.is_writeable()) and
					vmas_are_equal(left, right)):
					startlist.pop(k)
				else:
					k += 1
			j += 1

		#if len(startlist) != orig_len:
		#	print_debug(tag, ("now startlist: {}").format(startlist))
		dedup_vmas += startlist   # list concatenate		

	return dedup_vmas

# Returns a tuple: (a dict with the vmas inserted into lists by key
# returned from the query_fn; the total count of vmas in the vmalist
# (across all processes in the group) that were hashed into at least
# one slot in the dict).
def query_vmas_grouped(proc_group, query_fn, whichtable):
	tag = 'query_vmas_grouped'

	# Put the vmatables / all_vmas / cp_vmas from each process in the
	# group into a single list. This loses the key information (the
	# grouping by start-addr), but this is fine because the query_fn
	# doesn't consider this information anyway (it just processes a
	# single vma (vm_mapping object)). Because of this, we don't need
	# to keep the vma list sorted either.
	vmalist = get_group_vmalist(proc_group, whichtable)
	print_debug(tag, ("constructed vmalist with {} vmas grouped from {} "
		"processes (root: {})").format(len(vmalist), len(proc_group),
		proc_group[0].name()))

	print_debug(tag, ("now passing the vmalist and query_fn to "
		"construct_dict_from_list, which will run the query_fn "
		"on every vma in the list and return a tuple: (a dict with "
		"the vmas inserted into lists by key returned from the "
		"query_fn; the total count of vmas in the vmalist arg "
		"that were hashed into at least one slot in the dict)").format())
	return construct_dict_from_list(vmalist, query_fn)

#############################################################################

PRINT_SEGSET_CHANGES = True

class segment_set:
	"""docstring for segment_set class..."""
	tag = "class segment_set"

	# Members:
	seg_dict = None
	vmasize_to_segsize = None

	# vmasize_to_segsize is a function with prototype:
	#   vmasize_to_segsize(vmasize)
	#   Returns: the segment size that should be used for the specified vma
	#     size.
	# 
	def __init__(self, vmasize_to_segsize):
		tag = "{0}.__init__".format(self.tag)

		if not vmasize_to_segsize:
			print_error_exit(tag, ("some arg is None: "
				"vmasize_to_segsize={0}").format(
				vmasize_to_segsize))
		self.vmasize_to_segsize = vmasize_to_segsize
		self.reset()

	def reset(self):
		tag = "{0}.reset".format(self.tag)

		self.seg_dict = dict()
		return

	#def to_str(self):
	#	print_error_exit(self.tag, ("to_str() not implemented yet").format())

	# Add a segment corresponding to the specified vma size to the set
	# of segments that are being tracked *right now*.
	# Returns: a tuple (segsize, now, now_max)
	def add_to_now(self, vmasize):
		tag = "add_to_now"
		global PRINT_SEGSET_CHANGES

		segsize = self.vmasize_to_segsize(vmasize)
		try:
			(now, now_max, ever) = self.seg_dict[segsize]
			now += 1
			if now > now_max:
				now_max = now
		except KeyError:
			(now, now_max, ever) = (1, 1, 0)
		self.seg_dict[segsize] = (now, now_max, ever)
		if PRINT_SEGSET_CHANGES:
			print_debug(tag, ("seg_dict[{0}] = {1}").format(
				segsize, self.seg_dict[segsize]))

		return (segsize, now, now_max)

	# Add a segment corresponding to the specified vma size to the set
	# of segments that are being counted forever.
	# Returns: a tuple (segsize, ever)
	def add_to_ever(self, vmasize):
		tag = "add_to_ever"
		global PRINT_SEGSET_CHANGES

		segsize = self.vmasize_to_segsize(vmasize)
		try:
			(now, now_max, ever) = self.seg_dict[segsize]
			ever += 1
		except KeyError:
			(now, now_max, ever) = (0, 0, 1)
		self.seg_dict[segsize] = (now, now_max, ever)
		if PRINT_SEGSET_CHANGES:
			print_debug(tag, ("seg_dict[{0}] = {1}").format(
				segsize, self.seg_dict[segsize]))

		return (segsize, ever)

	# Removes a segment corresponding to the specified vma size from 
	# the set of segments that are being tracked *right now*. An error
	# will be raised if the number of segments tracked goes below zero.
	# Returns: a tuple (segsize, now, now_max)
	def remove_from_now(self, vmasize):
		tag = "remove_from_now"
		global PRINT_SEGSET_CHANGES

		segsize = self.vmasize_to_segsize(vmasize)
		try:
			(now, now_max, ever) = self.seg_dict[segsize]
			now = now - 1
			if now < 0:
				print_error_exit(tag, ("number of segments tracked "
					"for segsize {0} is below zero! (vmasize {1}, "
					"now_max {2}, ever {3}").format(
					segsize, vmasize, now_max, ever))
		except KeyError:
			print_error_exit(tag, ("called for a segsize {0} that "
				"has never been seen before! (vmasize {1})").format(
				segsize, vmasize))
		self.seg_dict[segsize] = (now, now_max, ever)
		if PRINT_SEGSET_CHANGES:
			print_debug(tag, ("seg_dict[{0}] = {1}").format(
				segsize, self.seg_dict[segsize]))

		return (segsize, now, now_max)

	# Returns the number of segments of the specified vma size (so the size
	# will be passed through the vmasize_to_segsize function first). Pass
	# vmasize == -1 to get the total number of segments of any size (the sum
	# of all of the now values in the dict).
	def count_now(self, vmasize):
		tag = "{0}.count_now".format(self.tag)
		
		if vmasize == -1:
			total = 0
			for (now, now_max, ever) in self.seg_dict.values():
				total += now
			return total
		else:
			try:
				count = self.seg_dict[self.vmasize_to_segsize(vmasize)]
			except KeyError:
				count = 0
			return count
	
	# now_or_ever should be "now" or "ever". plot_pdf is optional.
	# now_max is plotted on the same plot as "now".
	def plot(self, now_or_ever, plot_fname, title, plot_pdf):
		tag = "{0}.plot".format(self.tag)

		inefficient_segset = dict()
		for (key, value) in self.seg_dict.items():
			segsize = key
			(now, now_max, ever) = value
			if now_or_ever == "now":
				inefficient_segset[segsize] = (now, now_max)
			elif now_or_ever == "ever":
				# segset_to_plot() was initially written assuming two bars
				# for now and now_max... for now, just use ever count twice.
				inefficient_segset[segsize] = (ever, ever)
			else:
				print_error_exit(tag, ("invalid now_or_ever: {0}").format(
					now_or_ever))

		segset_to_plot(inefficient_segset, plot_fname, title, plot_pdf)

		return

#############################################################################

def add_to_stats_dict(stats, key, n):
	tag = "add_to_stats_dict"

	try:
		stats[key] += n
	except KeyError:
		#print_debug(tag, ("adding key {0} to stats dict").format(key))
		stats[key] = n
	print_debug(tag, ("incremented {0} count: {1}").format(
		key, stats[key]))
	return

def stats_to_str(stats):
	tag = "stats_to_str"

	if not stats:
		return "(stats is None)"

	s = []
	for key in sorted(stats.keys()):
		value = stats[key]
		s.append(("{0}:\t{1}").format(key, value))
	s = "\n".join(s)
	return s

def context_to_str(context):
	tag = "context_to_str"

	if not context:
		return "(context is None)"

	ctx_str = []
	for key in sorted(context.keys()):
		value = context[key]
		try:
			hexval = hex(value)
			ctx_str.append(("\t[{0}:\t{1} ({2})]").format(
				key, value, hexval))
		except TypeError:
			ctx_str.append(("\t[{0}:\t{1}]").format(
				key, value))
	ctx_str = "\n".join(ctx_str)

	return ctx_str

def segset_to_str(segset):
	tag = "segset_to_str"

	if not segset:
		return "(segset is None)"

	total_count = 0
	total_max = 0
	s = ["\tsegment-size\tcount\tmaxcount"]
	for key in sorted(segset.keys()):
		(count, maxcount) = segset[key]
		total_count += count
		total_max += maxcount
		s.append(("\t{0}\t{1}\t{2}").format(key, count, maxcount))
	s.insert(1, ("\t{0}\t{1}\t{2}").format("TOTAL", total_count, total_max))
	s = "\n".join(s)
	return s

def vmatable_to_str(vmatable):
	tag = "vmatable_to_str"

	if not vmatable:
		return "(vmatable is None)"

	s = ["\tstart_addr:\tmapping-size\tperms-key\tseg-size"]
	for key in sorted(vmatable.keys()):
		entry = vmatable[key]
		if entry.start_addr != key:   # sanity check
			print_error_exit(tag, ("segment table is inconsistent: key is "
				"{0}, but entry.start_addr is {1}!").format(hex(key),
				hex(entry.start_addr)))
		s.append(("\t{0}:\t{1}\t{2}\t{3}").format(
			hex(entry.start_addr), entry.length, entry.perms_key,
			entry.seg_size))
	s = "\n".join(s)
	return s

def segset_count(segset):
	tag = "segset_count"

	count = 0
	for (segcount, maxcount) in segset.values():
		count += segcount
	return count

def vmatable_count(vmatable):
	tag = "vmatable_count"

	return len(vmatable)

# Adds the second segset to the first segset. This method does not make
# a copy of the dict first, so the first segset is modified  (I think).
def segset_accumulate(dst, src):
	tag = "segset_accumulate"

	print_debug(tag, ("input src:\n{0}".format(segset_to_str(src))))
	print_debug(tag, ("input dst:\n{0}".format(segset_to_str(dst))))

	for segsize in sorted(src.keys()):
		(src_count, src_maxcount) = src[segsize]
		try:
			(dst_count, dst_maxcount) = dst[segsize]
			dst[segsize] = (dst_count + src_count,
				dst_maxcount + src_maxcount)
		except KeyError:
			dst[segsize] = (src_count, src_maxcount)
	
	print_debug(tag, ("accumulated segset:\n{0}".format(segset_to_str(dst))))
	return dst

# Adds a segment of the specified segsize to the segset dict.
def segset_append(segset, segsize):
	tag = "segset_insert"

	try:
		(count, maxcount) = segset[segsize]
		count = count + 1
		if count > maxcount:
			maxcount = count
	except KeyError:
		count = 1
		maxcount = 1
	segset[segsize] = (count, maxcount)

	return

# A vmatable is a dictionary whose keys are start-addresses and whose values
# are vm_mapping objects. A segset is a dictionary whose keys are segment
# sizes and whose values are tuples of the form (num-segments,
# max-num-segments).
def vmatable_startkey_to_segset(vmatable, vmasize_to_segsize):
	tag = "vmatable_startkey_to_segset"

	segset = dict()
	for (start_addr, vma) in vmatable.items():
		segsize = vmasize_to_segsize(vma.length)
		segset_append(segset, segsize)

	return segset

# Returns the closest power of 2 that is greater than n, starting from
# the minimum segment size. If n itself is a power of 2, then n will
# be returned.
def nextpowerof2(n):
	p = min_segment_size
	while p < n:
		p *= 2
	return p

if __name__ == '__main__':
	print_error_exit("not an executable module")
