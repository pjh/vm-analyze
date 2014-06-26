#! /usr/bin/env python3.3

# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from analyze.argparsers import *
from analyze.CheckpointEvent import CheckpointEvent
from analyze.cpus_tracker_class import *
from analyze.cpu_information_class import *
from analyze.ip_to_fn import *
from trace.run_common import *
from plotting.multiapp_plot_class import *
from analyze.PageEvent import PageEvent
from util.pjh_utils import *
from plotting.PlotEvent import PlotEvent
from analyze.process_group_class import *
from analyze.PTE import PTE, pte_get_linked_vma
from analyze.simulate_segments_lib import *
from analyze.vm_mapping_class import *
from conf.system_conf import *
import trace.vm_common as vm
import conf.PlotList
import plotting.plots_common as plots
import plotting.plot_os_overheads
import plotting.plot_vma_sizes
import plotting.plot_vaspace
import plotting.plot_vmacount
import os
import re
import shlex
import shutil
import sys

# Globals:
vmasize_to_segsize = nextpowerof2
  # "strategy" function to use for converting vma sizes to segment sizes.
ignore_fork_exec_events = True
  # If set to True, the analysis will ignore the trace events emitted
  # for duplicating and removing the mmap of a process that is
  # immediately exec'd after forking.
GLOBAL_EVENT_TYPES = ['checkpoint', 'sched']
  # trace_event_type's that are "global": not associated with a particular
  # pid.

##############################################################################

# Original design, which doesn't really work: used address of vma struct in
# kernel to keep track of unique vmas. It turns out that these addresses
# are re-used while the former vma is still in use, so this was junk.
# New design: just track vmas by their start-address, as I've done before.
#   Actually, after discovering that user-threads appear as different pids
#   in the trace output, which was causing "hiding" of some trace events
#   when I filtered based on process name-pid, now it seems like this original
#   design might actually work when all of the events are present. Could
#   try it again...


# Takes a vma defined by the maps_line and either inserts it into the
# vmatable (action "map") or removes it from the vmatable (action "unmap").
# The unique "key" for each vma is its start-address. Attempting to map a
# vma that is already mapped or unmap a vma that is not already mapped will
# result in an error.
def map_unmap_vma(action, vma_match, proc_info, vma_op, timestamp,
		usermodule, userfn, proc_tracker):
	tag = "map_unmap_vma: [{}-{}]".format(vma_op, action)
	global vmasize_to_segsize

	if not vma_match:
		print_error_exit(tag, ("event_msg part of line didn't "
			"match mmap event regex").format())

	vmatable = proc_info.get_vmatable()
	strict = proc_info.be_strict()
	progname = proc_info.get_progname()

	# Get the fields from the mmap_vma event trace:
	#   Don't use pid / tgid / ptgid from vma_match - use what is already
	#   set in the proc_info!
	kernel_fn  = vma_match.group('fn_label').strip()
	vma_addr  = vma_match.group('vma_addr')
	maps_line = vma_match.group('rest')
	tag = "{} [{}]".format(tag, kernel_fn)
	vma_addr = int(vma_addr, 16)
	maps_line = maps_line.strip()

	maps_match = maps_line_re.match(maps_line)
	if not maps_match:
		print_error_exit(tag, ("maps_line part of line didn't match "
			"maps line regex: {0}").format(maps_line))
	(begin_addr, end_addr, perms, offset, dev_major, dev_minor,
		inode, filename) = maps_match.groups()
	begin_addr = int(begin_addr, 16)
	end_addr = int(end_addr, 16)
	length = end_addr - begin_addr
	perms_key = construct_perms_key(perms, inode, filename)
	offset = int(offset, 16)
	dev_major = int(dev_major, 16)
	dev_minor = int(dev_minor, 16)
	inode = int(inode)
	filename = filename.strip()
	seg_size = vmasize_to_segsize(length)

	# Ok, the encoding of "operations", "actions", and mappings vs. frees
	# in the vma object is a little strange. What do we need to know, and
	# how is it (or should it be) encoded in the vma fields?
	#   vma_op: tells us the operation responsible for the allocation
	#     of this particular vma at this particular begin_addr. EVERY
	#     vma is "initially" mapped by an 'alloc' op, but that "initial"
	#     vma may be unmapped and then remapped, in which case its vma_op
	#     will be set to 'access_change', 'resize', etc. Currently,
	#     vma_op is NEVER set to 'free'!
	#  unmap_op: the operation responsible for the unmapping of this
	#     vma. The complement of unmap_op: will never be set to 'alloc',
	#     will be set to 'free' on a "permanent" unmapping of a vma,
	#     otherwise will be set to 'resize', 'relocation', 'access_change',
	#     or 'flag_change' on the unmap part of an unmap-remap pair.
	#  is_unmapped: set to True (and unmap_timestamp set) when this vma
	#    is removed from the process' vmatable (its "memory map"). This
	#    may occur as part of an unmap-remap operation (in which case
	#    a new vma will be created for the remap, which represents the
	#    *operation*), 
	#      SO, a query / plot that is concerned with operation types can
	#      count up exactly the number of each type of operation by
	#      looking at the vma_op of every vma, no matter whether or not
	#      it is unmapped or not - every operation (alloc, resize,
	#      access_change...) will cause EXACTLY ONE vma to be created,
	#      with vma_op set to that operation. However, this examination
	#      will not work to count the number of *explicit* vma frees.
	# So, for the purposes of tracking vma *counts*, only vma_ops of
	# 'alloc' and unmap_ops of 'free' will change the count of vmas in
	# the address space. For tracking the total *size* of the virtual
	# address space, we must track the initial alloc vma_ops and final
	# free unmap_ops, AND we must also count 'resize' unmap_ops and
	# 'resize' vma_ops!

	# vmas are kept track of in two places for each process. "vmatable"
	# in the process_info object keeps track of the vmas that are *currently*
	# present in the process' memory map. "all_vmas" keeps track of all of
	# the vmas that were *ever* added to the process' memory map. So, when
	# the action is "map", we create a new vm_mapping (vma) object and
	# add it to both the process' vmatable and all_vmas. When the action
	# is "unmap", we remove the vma from the vmatable mapping, but don't
	# remove it from all_vmas, just mark it as unmapped.

	# When a fork-exec happens, here's the pattern of trace events that are
	# expected:
	#   dup_mmap (many)
	#   __bprm_mm_init (one)
	#   expand_downwards (one or more unmap-remap pairs)
	#   exit_mmap -> remove_vma (many)
	#   shift_arg_pages (one unmap-remap pair, with a disable-enable-sim
	#                    in the middle)
	# Most of the time these events can be handled here without any
	# special consideration for the vmatable - none of the mapped vmas
	# overlap, and all of the unmapped vmas were already present in
	# the vmatable. However, it turns out that the "mmap" (set of vmas)
	# that is operated on in these kernel functions is different in
	# __bprm_mm_init and expand_downwards - these two functions operate
	# on a single lone vma (bprm->vma, the first and only vma present in
	# bprm->mm) that is used for setting up the newly-exec'd process.
	# Unfortunately, the old mmap (current->mm) is still around when
	# this special vma is operated on, meaning that it is possible for
	# the special new bprm->vma to overlap with one of the old vmas that
	# is about to be freed by the many exit_mmap events. It took a long
	# time for this case to happen (usually the bprm->vma address doesn't
	# overlap with an existing vma), but I did see these events in one
	# kernelbuild trace:
	#   mmap_vma_alloc_dup_mmap: pid=16783 tgid=16783 ptgid=16782
	#     [dup_mmap]: ffff8801197e98a0 @ 7fffffffd000-7ffffffff000 r-xp
	#   mmap_vma_alloc: pid=16783 tgid=16783 ptgid=16782
	#     [__bprm_mm_init]: ...
	#   mmap_vma_resize_unmap: pid=16783 tgid=16783 ptgid=16782
	#     [expand_downwards]: ffff8801197e9cf0 @ 7ffffffff000-7ffffffff000
	#   mmap_vma_resize_remap: pid=16783 tgid=16783 ptgid=16782
	#     [expand_downwards]: ffff8801197e9cf0 @ 7fffffffe000-7ffffffff000
	#   mmap_vma_resize_unmap: pid=16783 tgid=16783 ptgid=16782
	#     [expand_downwards]: ffff8801197e9cf0 @ 7fffffffe000-7ffffffff000
	#   mmap_vma_resize_remap: pid=16783 tgid=16783 ptgid=16782
	#     [expand_downwards]: ffff8801197e9cf0 @ 7fffffffd000-7ffffffff000
	#       THE ADDRESS 7fffffffd000 OVERLAPS THE VMA REMOVED BELOW:
	#   ...
	#   mmap_vma_free: pid=16783 tgid=16783 ptgid=16782
	#    [exit_mmap -> remove_vma]: ffff8801197e98a0 @ 7fffffffd000-7ffffffff000
	#   ...
	#   mmap_vma_reloc_unmap: pid=16783 tgid=16783 ptgid=16782
	#     [shift_arg_pages]: ffff8801197e9cf0 @ 7fffffffd000-7ffffffff000
	#   ...
	#   (note: more expand_downwards events may happen down here too, not
	#    directly as part of the exec)
	# So, to handle the special overlapping vma, we store it in a special
	# "bprm_vma" in the proc_info until we hit a shift_arg_pages event, at
	# which point we make it the first vma in the vmatable. We need another
	# flag, "use_bprm", set to true in between the __bprm_mm_init and the
	# shift_arg_pages events, so that we know if the expand_downwards
	# events should use the special bprm_vma or the vmatable. Whew.
	#   To debug all of this, grep for "special" in this script's debug
	#   output...
	#   This new special-case handling should also work fine for the
	#   kernelbuild case where a clone-without-dup-mmap followed by
	#   exec is performed - the __bprm_mm_init -> expand_downwards ->
	#   shift_arg_pages sequence is the same, there's just no series
	#   of exit_mmap events in the middle.
	# 
	# Update: it turns out that the pattern above can change somewhat -
	# in a vmware-vmx trace, I observed an mprotect_fixup unmap-remap
	# that happened between the last exit_mmap and the expected
	# shift_arg_pages.
	#    Better way of using bprm_vma: once bprm_mm_init maps the first
	#    bprm_vma, keep using it for all events except for exit_mmap
	#    *as long as* len(vmatable) > 0. Once we get a non-exit_mmap
	#    event with len(vmatable) == 0, we know that the bprm_vma should
	#    now become the first vma used for this process.

	returnvma = None

	if action == "map":
		new_vma = vm_mapping(begin_addr, length, perms_key, seg_size,
			vma_op, offset, dev_major, dev_minor, inode, filename,
			timestamp, usermodule, userfn, kernel_fn, appname=progname)
		insert_into_vmatable = True

		# Starting an exec or in the process of performing an exec (before
		# exit_mmap begins):
		if (kernel_fn == '__bprm_mm_init' or proc_info.use_bprm):
			if proc_info.bprm_vma != None:
				print_error_exit(tag, ("special {} event, but bprm_vma is "
					"not None: {}").format(kernel_fn,
					proc_info.bprm_vma.to_str()))
			#if proc_info.use_bprm and len(vmatable) == 0:
			#   Don't check this - the expand_downwards remap after
			#   the __bprm_mm_init but before the exit_mmaps will
			#   have use_bprm set and len(vmatable) == 0.
			proc_info.bprm_vma = new_vma
			proc_info.use_bprm = True
			insert_into_vmatable = False
			print_debug(tag, ("special kernel_fn {}: map: set bprm_vma "
				"to new_vma, use_bprm to True, and will not insert "
				"into vmatable").format(kernel_fn))

		else:
			try:
				# We now consider it an error if we attempt to map a vma that
				# is already mapped; the trace events that I've added to the
				# kernel should unmap vmas before modifying and then remapping
				# them.
				# I think we can always be strict here: if we missed anything
				# before the trace started, it would be an existing mapping
				# that isn't present in our vmatable, not the opposite (here).
				# So, use print_error_exit, not print_unexpected.
				old_vma = vmatable[begin_addr]
				print_error_exit(tag, ("while attempting to map new vma [{0}], "
					"found existing vma at same begin_addr, [{1}]").format(
					new_vma.to_str_maps_format(),
					old_vma.to_str_maps_format()))
			except KeyError:
				pass  # expected case

		if insert_into_vmatable:
			# todo: these two lines (insert a vma into the process_info's
			# vmatable, track_vm_size) should be one method call on the
			# proc_info...
			vmatable[begin_addr] = new_vma
			if ignore_vma(new_vma):
				debug_ignored(tag, ("vmacount_datafn: not passing ignored "
					"mapped vma to track_vm_size()").format())
			else:
				track_vm_size(proc_info, proc_tracker, 'add',
						new_vma.length, timestamp)

			print_debug(tag, ("{}: tgid={}: vmatable[{}] = "
				"{}").format(action, proc_info.pid, hex(begin_addr),
				new_vma.to_str_maps_format()))
			debug_vmsize_old(tag, proc_info.pid,
				("INSERT: tgid={}: vmatable[{}] = {}").format(
				proc_info.pid, hex(begin_addr), new_vma))
			debug_vmsize_old(tag, proc_info.pid,
				("total_vm_size={}").format(
				pretty_bytes(proc_info.total_vm_size)))
		
		# I think we always want to add_to_all_vmas, for stats purposes;
		# otherwise, the alloc + resize(s) done by __bprm_mm_init and
		# expand_downwards etc. would be lost.
		proc_info.add_to_all_vmas(new_vma)
		returnvma = new_vma
	
	elif action == "unmap":
		unmapped_vma = None

		# Note: this code will only work if there is just a single
		# unmap-remap pair (while the sim is enabled) in shift_arg_pages!
		# If there is more than one unmap-remap pair, then the first remap
		# will hit the normal case above, but then the second unmap will
		# hit the special case right here and will try to use bprm_vma,
		# which should no longer be used.
		if (proc_info.use_bprm and not is_exit_event(vma_match)):
			if not proc_info.bprm_vma:
				print_error_exit(tag, ("special {} event, but bprm_vma is "
					"None!").format(kernel_fn))
			unmapped_vma = proc_info.bprm_vma
			proc_info.bprm_vma = None

			# First event after exit_mmap events have completed.
			# Ugh, crap - just checking for len(vmatable) == 0 doesn't
			# work here, because when we're skipping fork events
			# (dup_mmap and exit_mmap), the vmatable just-started (and
			# just-exec'd) process starts as empty, so the
			# expand_downwards unmap-remap that comes just after the
			# __bprm_mm_init would cause this code to reset bprm
			# and exec_follows_fork!
			#   Ugh - well, just don't enter this condition for
			#   expand_downwards events, which so far is the only
			#   event type that pops up in-between the __bprm_mm_init
			#   and the exit_mmap.
			if len(vmatable) == 0 and kernel_fn != 'expand_downwards':
				# At this point we know that the fork-exec is "complete" -
				# all of the exit_mmap events have passed, and the mmap
				# should be empty. So, in addition to no longer using the
				# special bprm_vma, we ALSO need to set exec_follows_fork
				# to False, so that any future forks / execs are handled
				# correctly. If we don't do this, then a process like
				# Chrome, which starts with a fork-exec and then later
				# performs another exec, will be handled incorrectly
				# (we'll skip the exit_mmap events for the second exec
				# when we should not).
				proc_info.use_bprm = False
				proc_info.set_exec_follows_fork(False)
				print_debug(tag, ("special kernel_fn {}: unmap: bprm_vma "
					"set to None and use_bprm set to False, so no more "
					"special bprm handling for this process. Also set "
					"exec_follows_fork to False since this fork-exec can "
					"be considered complete, and another fork-exec or "
					"just exec could follow later").format(
					kernel_fn))
			else:
				print_debug(tag, ("special kernel_fn {}: unmap: bprm_vma "
					"set to None, but use_bprm still True, so any "
					"non-exit_mmaps that follow will still be handled "
					"specially").format(kernel_fn))

		else:   # normal case
			try:
				# We remove the vma from the vmatable, but it will still be
				# present in the data structure that tracks the vmas that were
				# *ever* used by this process. Mark it as unmapped (below)
				# so that we can tell later.
				# todo: these two lines (remove a vma from the process_info's
				# vmatable, track_vm_size) should be one method call on the
				# proc_info...
				unmapped_vma = vmatable.pop(begin_addr)
				if ignore_vma(unmapped_vma):
					debug_ignored(tag, ("vmacount_datafn: not passing "
						"ignored unmapped vma to track_vm_size()").format())
				else:
					track_vm_size(proc_info, proc_tracker, 'sub',
							unmapped_vma.length, timestamp)

				debug_vmsize_old(tag, proc_info.pid,
					("DELETE: tgid={}: vmatable[{}] = "
					"{}").format(proc_info.pid, hex(begin_addr),
					unmapped_vma))
				debug_vmsize_old(tag, proc_info.pid,
					("total_vm_size={}").format(
					pretty_bytes(proc_info.total_vm_size)))

			except KeyError:
				# Check for rare "race condition" where we start the trace
				# just after a process' fork but before its exec, causing
				# us to see unmap events that happen during exec for vmas
				# that we don't know about.
				if (proc_info.saw_exec and not proc_info.saw_fork and
						'exit_mmap' in kernel_fn):
					print_warning(tag, ("hit unusual condition where "
						"trace started between process' fork and exec: "
						"saw_exec is true but saw_fork is not, and "
						"process is now unmapping vmas that we don't "
						"know about from the duplicated mmap.").format())
				else:
					print_unexpected(strict, tag, ("strict={}: "
						"attempting to unmap a vma at begin_addr {} "
						"that is not in vmatable of process tgid={}. "
						"Line from trace event: {}").format(strict,
						hex(begin_addr), proc_info.pid, maps_line))
				unmapped_vma = None
				returnvma = None

		# We want to execute all of this code for both cases: special
		# kernel fn unmappings, or normal unmappings that were found in
		# the vmatable.
		if unmapped_vma:
			unmapped_vma.mark_unmapped(timestamp, vma_op)
			print_debug(tag, ("{}: tgid={}: removed vmatable[{}] = "
				"{}").format(action, proc_info.pid, hex(begin_addr),
				unmapped_vma.to_str_maps_format()))

			# If we've reached this far, then we know that we unmapped
			# *something* from our vmatable, and if it was in the
			# vmatable to begin with then we expect it to be an accurate
			# vma. Therefore, our checking here should always be strict
			# (but we may wish to override during debugging).
			if True:
				strict_check = True
				override = False
				if override:
					strict_check = False
					print_warning(tag, ("overriding strict_check").format())
				# Compare vma in the vmatable to the properties coming from
				# the mmap line in the trace event:
				if unmapped_vma.length != length:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"length {} does not match trace event's length "
						"{}").format(
						pretty_bytes(unmapped_vma.length),
						pretty_bytes(length)))
				if unmapped_vma.perms_key != perms_key:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"perms_key {} does not match trace event's perms_key "
						"{}").format(
						unmapped_vma.perms_key, perms_key))
				if unmapped_vma.seg_size != seg_size:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"seg_size {} does not match trace event's seg_size "
						"{}").format(
						pretty_bytes(unmapped_vma.seg_size),
						pretty_bytes(seg_size)))
				if unmapped_vma.offset != offset:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"offset {} does not match trace event's offset "
						"{}").format(
						unmapped_vma.offset, offset))
				if unmapped_vma.dev_major != dev_major:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"dev_major {} does not match trace event's dev_major "
						"{}").format(
						unmapped_vma.dev_major, dev_major))
				if unmapped_vma.dev_minor != dev_minor:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"dev_minor {} does not match trace event's dev_minor "
						"{}").format(
						unmapped_vma.dev_minor, dev_minor))
				if unmapped_vma.inode != inode:
					print_unexpected(strict_check, tag, ("unmapped vma's "
						"inode {} does not match trace event's inode "
						"{}").format(
						unmapped_vma.inode, inode))
				if unmapped_vma.filename != filename:
					# I hit this one time for:
					#   /home/pjh/.mozilla/firefox/el40yjml.default-136
					#   8472778514/healthreport.sqlite-shm does not match
					#   trace event's filename /home/pjh/.mozilla/firef
					#   ox/el40yjml.default-1368472778514/healthreport.
					#   sqlite-shm (deleted) - exiting.
					if (unmapped_vma.filename in filename or
						filename in unmapped_vma.filename or
						'shm' in unmapped_vma.filename):
						print_debug(tag, ("unmapped_vma's filename {} "
							"doesn't exactly match trace event's filename "
							"{}, but ignoring because one is a substring "
							"of the other or because 'shm' is in the "
							"filename, indicating a shared memory "
							"region").format(unmapped_vma.filename,
							filename))
					else:
						print_unexpected(strict_check, tag, ("unmapped "
							"vma's filename {} does not match trace "
							"event's filename {}").format(
							unmapped_vma.filename, filename))
			returnvma = unmapped_vma

	else:
		print_error_exit(tag, ("unknown action {0}").format(action))

	debug_vmsize_old(tag, proc_info.pid, ("tgid={}: returnvma "
		"= {}").format(proc_info.pid, returnvma))
	if False:
		#proc_info.write_proc_map(sys.stderr)
		sorted_vmas = sorted(proc_info.vmatable.values(),
				key=lambda vma: vma.start_addr)
		for V in sorted_vmas:
			debug_ignored(tag, ("map: {}").format(V))
		#debug_ignored(tag, ("").format())

	return returnvma

# Raises an error if there are any trace events present in the process
# context dict. This is mostly a sanity-checking method; it's pretty
# fragile.
def check_context_for_event_pairs(proc_context):
	tag = "check_context_for_event_pairs"

	for key in proc_context.keys():
		if key in VMA_OP_TYPES:
			# I think we can always be strict here: print_error_exit,
			# rather than print_unexpected.
			print_error_exit(tag, ("found at least one existing "
				"trace event in proc_context when expected to find "
				"none: proc_context[{0}] = {1}").format(
				key, proc_context[key]))
	return

# ...
def begin_event_pair(vma_op, proc_info, vma_match):
	tag = "begin_event_pair"
	strict = proc_info.be_strict()
	proc_context = proc_info.get_context()

	# Currently, we only expect one "event pair" to ever be "active"
	# at any moment, so when begin_event_pair() is first called we
	# check that the process context has no outstanding trace events.
	if vma_op not in VMA_OP_TYPES:
		print_error_exit(tag, ("vma_op {0} not in list of VMA_OP_TYPES "
			"{1}").format(vma_op, VMA_OP_TYPES))
	check_context_for_event_pairs(proc_context)

	if not vma_match:
		print_error_exit(tag, ("vma_match is None").format())
	vma_addr = int(vma_match.group('vma_addr'), 16)
	maps_line = vma_match.group('rest')
	line_match = maps_line_re.match(maps_line)
	if not line_match:
		print_error_exit(tag, ("maps_line_re match failed on {}").format(
			maps_line))
	perms = line_match.group('perms')

	try:   # sanity check
		# I think we can always be strict here:
		existing_vma_addr = proc_context[vma_op]
		print_error_exit(tag, ("got proc_context[{0}] = "
			"{1}, but expected nothing! new vma_addr={2}").format(
			vma_op, hex(existing_vma_addr), hex(vma_addr)))
	except KeyError:   # expected case
		proc_context[vma_op] = vma_addr
		proc_context["{}-perms".format(vma_op)] = perms
		#print_debug(tag, ("saved proc_context[{0}] = {1}").format(
		#	vma_op, hex(vma_addr)))

	return

# If addr_must_match is true, then the address that is passed via the
# vma_match object now will be checked against the address that was
# stored by begin_event_pair. Some event pairs will want to set
# addr_must_match to false, e.g. relocate and resize events, for
# which the start-addr of the vma may change.
def end_event_pair(vma_op, proc_info, vma_match, addr_must_match):
	tag = "end_event_pair"
	#strict = proc_info.be_strict()
	proc_context = proc_info.get_context()

	if vma_op not in VMA_OP_TYPES:
		print_error_exit(tag, ("vma_op {0} not in list of VMA_OP_TYPES "
			"{1}").format(vma_op, VMA_OP_TYPES))

	if not vma_match:
		print_error_exit(tag, ("vma_match is None").format())
	vma_addr = int(vma_match.group('vma_addr'), 16)
	maps_line = vma_match.group('rest')
	line_match = maps_line_re.match(maps_line)
	if not line_match:
		print_error_exit(tag, ("maps_line_re match failed on {}").format(
			maps_line))
	perms = line_match.group('perms')

	try:   # expected case
		existing_vma_addr = proc_context.pop(vma_op)
		if existing_vma_addr != vma_addr:
			if addr_must_match:
				print_error_exit(tag, ("got proc_context[{0}] = {1}, "
					"which doesn't match vma_addr {2}!").format(
					vma_op, hex(existing_vma_addr), hex(vma_addr)))
			else:
				print_warning(tag, ("got proc_context[{0}] = {1}, "
					"which doesn't match vma_addr {2} now - check that "
					"this makes sense for this trace event").format(
					vma_op, hex(existing_vma_addr), hex(vma_addr)))
		#print_debug(tag, ("removed proc_context[{0}] = {1}").format(
		#	vma_op, hex(existing_vma_addr)))
		saved_perms = proc_context.pop("{}-perms".format(vma_op))
		if (vma_op != 'access_change' and saved_perms != perms):
			print_unexpected(strict, tag, ("for non-access-change op "
				"{}, permissions changed from {} to {}!").format(
				vma_op, saved_perms, perms))
	except KeyError:   # unexpected
		strict = proc_info.be_strict()
		print_unexpected(strict, tag, ("didn't find an existing vma "
			"saved for proc_context[{0}]! vma_addr={1}").format(
			vma_op, hex(vma_addr)))

	# Currently, we only expect one "event pair" to ever be "active"
	# at any moment, so when end_event_pair() is complete we check
	# that the process context has no outstanding trace events.
	check_context_for_event_pairs(proc_context)

	return

return_underflow_count = 0
mem_target_not_found = 0
#UNDERFLOW_LABEL = '(underflow)'
UNDERFLOW_LABEL = 'kernel(setup-teardown)'
MODULE_DISABLED = 'userstacktrace-disabled'
FN_KERNEL = 'fn-in-kernel'
FN_ANON = 'fn-in-anon-mapping'
FN_LOOKUPERR = 'fn-lookup-error'
FN_LOOKUPFAIL = 'fn-lookup-failed'
FN_DISABLED = 'fn-lookup-disabled'

# The get_current_module() and get_current_fn() methods should possibly
# be integrated into the process_info class, along with the rest of the
# callstack manipulation that's done throughout this script...
#
# If there are no entries on the callstack, UNDERFLOW_LABEL is used for
# the module and the fn_label argument is used for the function (e.g.
# the name of a kernel event, perhaps).
#
# Returns None if the callstack could not be gotten.
def get_current_module(proc_info, fn_label):
	return __get_current_module_or_fn(proc_info, fn_label, 'module')

def get_current_fn(proc_info, fn_label):
	return __get_current_module_or_fn(proc_info, fn_label, 'fn')

# Internal helper method.
def __get_current_module_or_fn(proc_info, fn_label, module_or_fn):
	tag = "__get_current_module_or_fn"
	global UNDERFLOW_LABEL

	try:
		callstack = proc_info.get_context()['callstack']
		if len(callstack) == 0:
			module = UNDERFLOW_LABEL
			fn = module + '+' + fn_label
		else:
			fn = callstack[-1]
			(module, plus, stack_fn) = fn.partition('+')
	except KeyError:
		print_warning(tag, ("failed to get callstack from proc_info's "
			"context").format())
		return None

	if module_or_fn == 'module':
		return module
	elif module_or_fn == 'fn':
		return fn
	else:
		print_error_exit(tag, ("bad module_or_fn: {0}").format(
			module_or_fn))

# A hash function used for mapping the vmas in every process_info's
# "all_vmas" tracker.
def vma_hash_size(vma):
	return vma.seg_size

# A hash function used for mapping the vmas in every process_info's
# "all_vmas" tracker.
def vma_hash_perms(vma):
	return vma.perms_key

# Allocates and initializes a new process_info struct, then inserts it
# into the specified process_tracker.
def new_proc_info(pid, proc_tracker):
	tag = "init_proc_info"

	proc_info = process_info(pid)
	proc_tracker.insert_process_info(proc_info)
	print_debug(tag, ("added new process_info to proc_tracker: "
		"{0}").format(pid))

	# Note: proc_info.saw_fork and proc_info.saw_exec should have been 
	# set to False in constructor.

	# The choice of hash function doesn't really matter for functionality,
	# because the process_info "query" functions can be used to obtain
	# a vma mapping based on arbitrary conditions, but the hash function
	# used can matter for performance: if the query function that we use
	# matches the hash function used to originally keep track of all_vmas,
	# then a copy of the all_vmas mapping can just be returned directly,
	# rather than constructing an entirely new mapping.
	#   Note: after implementing this code and validating it, I swapped
	#   the hash function that's used here and verified that the output
	#   was identical.
	#proc_info.set_vma_hash_fn(vma_hash_size)
	proc_info.set_vma_hash_fn(vma_hash_perms)
			
	ctx = proc_info.get_context()

	# Some trace messages may want to temporarily disable this
	# simulation code. Keep track of this at a per-process
	# granularity; otherwise, if tracked globally, then processes
	# running concurrently on separate CPU cores may interfere
	# with each others' simulations.
	ctx['sim_enabled'] = True

	# Other context initialization...
	# Using lists as stacks:
	#   http://docs.python.org/3/tutorial/datastructures.html#
	#   using-lists-as-stacks

	return proc_info

'''
def reset_sim_for_proc(proc_info):
	tag = "reset_sim_for_proc"
	#global firstexec_str

	# reset_sim_data should do most of the work (e.g. resetting vmatable
	# and all_vmas), but we may need to adjust the context dict:
	#   sim_enabled: unchanged
	#   callstack: unchanged
	#   vma ops (begin/end_event_pair): unchanged
	proc_info.reset_sim_data('full')
	
	## We usually don't want to clear the entire process context,
	## but there may be a few things we want to reset:
	#ctx = proc_info.get_context()
	#ctx.pop(firstexec_str, None)   # see process_userstack_events()

	print_debug(tag, ("reset vma tracking data for {0}-{1}").format(
		proc_info.get_pid(), proc_info.get_progname()))

	return
'''

# 
def end_final_sched_quantum(cpu_tracker, proc_tracker):
	tag = "end_final_sched_quantum"

	for cpu_info in cpu_tracker.get_all_cpu_infos():
		cpu_pid = cpu_info.get_current_pid()
		proc_info = proc_tracker.get_process_info(cpu_pid)
		if not proc_info:
			print_error_exit(tag, ("get_process_info for pid {0} which "
				"is current on cpu failed").format(cpu_pid))

	return

def handle_sched_switch(pid_switched_out, proc_tracker):
	tag = "handle_sched_switch"

	proc_info = proc_tracker.get_process_info(pid_switched_out)
	if not proc_info:
		# I think we expect to see this fairly regularly: processes
		# may be switched in before we've seen any of their vma events,
		# and they may not emit any vma events at all during the entire
		# trace.
		print_warning(tag, ("no proc_info yet for pid {0} - this is "
			"probably fine").format(pid_switched_out))
		return

	# For efficiency, don't bother tracking quantum counts for processes
	# that are not (yet) being traced by pin. As soon as the first Pin
	# event (Read, Write, or Call / Tailcall) is hit, the traced_by_pin
	# flag will be set, and we will make the end_sched_quantum() call
	# below the very next time the target process is switched out,
	# without any loss of measurement.
	if not proc_info.is_traced_by_pin():
		#print_debug(tag, ("skipping sched quantum stuff for process "
		#	"{0}-{1} - not being traced by pin (yet)").format(
		#	proc_info.get_progname(), proc_info.get_pid()))
		return

	proc_info.end_sched_quantum()

	return

firstexec_str = 'firstexec_ip'

# When this method is called after a kernel trace event has been read
# from the trace_f, it will look for and process any userstacktrace
# events FOR THE SPECIFIED CPU, if they follow in the trace file. This
# method will peek forward at lines that follow in the trace_f, but
# it will reset the file pointer back to the location it was at when
# this method was entered.
#
# This method is not affected by the group_multiproc flag - it just
# figures out what process is "responsible" for the user stack trace,
# then looks at the vmas for that process (even when group_multiproc
# is true, vmas must be tracked for each separate process), and then
# just returns usermodule and userfn strings; no "stats" are accounted
# here.
# 
# Returns: a string representing the "usermodule" responsible for the
# most-recent kernel trace event, or None if no userstacktrace lines
# for the specified cpu were found.
def process_userstack_events(ip_to_fn, trace_f, linenum,
		event_task, mmap_pid, proc_tgid, event_cpu, proc_tracker,
		is_fork_event, is_exec_event):
	tag = "process_userstack_events"
	global MODULE_KERNEL
	global MODULE_ANON
	global firstexec_str
	global badtrace_str
	global mod_fn_sep

	debug_this_method = False
	def print_debug_userstack(tag, msg):
		if debug_this_method:
			print_debug(tag, msg)
	debug_just_modules = True

	original_pos = trace_f.tell()
	stack_proc_info = None
	reason = None

	# Keep track of the code modules and functions as we process the
	# userstacktrace, from the top (most-recent calls) to the bottom.
	# Invariant: the length of the usermodule and userfn lists should
	# be equal after processing every userstacktrace entry!
	usermodule = []
	userfn = []

	while True:
		line = trace_f.readline()
		linenum += 1
		if not line:
			break
		if line[0] == '#':   # skip comment lines
			continue

		# Get the cpu from the trace event line (no matter the type
		# of event - we're assuming with this regex search that the
		# first set of [digits] in brackets is the cpu! If the cpu
		# doesn't match the cpu passed into this method, skip this
		# line until we find a line whose cpu does match.
		line_cpu_match = trace_event_cpu_re.search(line)
		if not line_cpu_match and line[0] != '#':
			print_error_exit(tag, ("line {0} in trace input failed "
				"trace_event_cpu_re search - this is unexpected now "
				"that Pin is not used, right? {1}").format(
				linenum, line))
		line_cpu = int(line_cpu_match.group('cpu'))
		if line_cpu != event_cpu:
			print_debug_userstack(tag, ("skipping line {0} from cpu {1} that "
				"is interleaved with events from \"target\" cpu "
				"{2}").format(linenum, line_cpu, event_cpu))
			continue

		# Ok, we have a line that matches the "target" event_cpu. If
		# it's a <user stack trace> begin line, verify the pid/tgid,
		# get the proc_info object, and then keep going through the
		# file. If it's a userstacktrace entry line, process it and
		# keep going. Otherwise, stop looping through the file.
		#
		# Put the check for a userstacktrace entry first - it's
		# probably the most common. I could further optimize this
		# loop if I really want...
		stack_entry_match = userstacktrace_entry_re.match(line)
		if stack_entry_match:
			if not stack_proc_info:
				print_error_exit(tag, ("hit a userstacktrace entry "
					"line {0} before hitting a userstacktrace begin "
					"line - stack_proc_info not set yet!").format(
					linenum))
			(entrymodule, entryfn) = (None, None)

			# Take the instruction pointer listed in the stack entry
			# and find the virtual memory mapping that contains it.
			# We expect the containing vma to be a *code* region.
			#
			# Also, we want to keep track of the first ip that is
			# seen during an *exec*. During the exec, many kernel
			# vma events will appear in the trace, including a
			# sequence of exit_mmap events that destroy the process'
			# memory map, then a sequence of events that install
			# the initial process vmas. During these events the
			# process should, I believe, only have a single ip in
			# its userstacktrace, and that ip will not change until
			# the exec is complete and control returns to the process.
			# So, if we don't find any matching vmas but the ip
			# matches this firstexec ip, it is safe to ignore this no-match
			# and attribute the event to the kernel.
			#  -Unfortunately, just looking at is_exec_event alone is
			#   not sufficient, because there are vma events that happen
			#   during an exec that could just as easily happen at any
			#   other time during process execution.
			#  -Also, note that some processes may perform more than one
			#   exec during their lifetime, without a fork; for example,
			#   during one firefox trace I saw the same python process
			#   emit __bprm_mm_init trace events at least twice. To make
			#   sure that this is handled appropriately here, I first tried
			#   to add a line in reset_sim_for_proc() that removes the
			#   firstexec_ip that is remembered... but this doesn't work
			#   because the firstexec_ip is still needed after the reset.
			#   So instead I just turned the error below into a warning,
			#   and we override the firstexec_ip that is already stored.
			#
			# Also note: sometimes, if the stack unwind from the kernel
			# hits an entry with ip == 0, it will print out a line like
			# " [001] => ??". I updated the userstacktrace_entry_re to
			# match this line as well - when this is encountered, the
			# 'ip' group will be None and the 'ipnotfound' group will
			# be '??'. When we encounter an ip-not-found entry, what
			# should we do here? I think it's easy + fine to just set
			# the ip to 0 and go forward - this will result in the vma
			# not being found, and UNKNOWN_MODULE and UNKNOWN_FN will
			# be used. All of this seems to make perfect sense.
			ipstr = stack_entry_match.group('ip')
			if ipstr != None:
				ip = int(stack_entry_match.group('ip'), 16)
			else:
				if stack_entry_match.group('ipnotfound') != '??':
					print_error_exit(tag, ("got ipstr={}, but "
						"ipnotfound group={}").format(ipstr,
						stack_entry_match.group('ipnotfound')))
				ip = 0
				stack_proc_info.add_to_stats(
					'userstack-ip-equals-0', 1)
			try:
				firstexec_ip = stack_proc_context[firstexec_str]
				if is_exec_event:
					print_warning(tag, ("is_exec_event is true but "
						"firstexec_ip is already set - is this right? "
						"When is_exec_event is used to represent just "
						"the first exec event (__bprm_mm_init), then "
						"this case should only be hit when a process "
						"performs more than one exec during its lifetime. "
						"Line {0}").format(linenum))
					firstexec_ip = ip
					stack_proc_context[firstexec_str] = firstexec_ip
			except KeyError:
				if is_exec_event:
					firstexec_ip = ip
					stack_proc_context[firstexec_str] = firstexec_ip
				else:
					firstexec_ip = None

			vma = find_vm_mapping(stack_proc_info, ip, starts_at=False,
				remove=False)
			if vma:
				if not debug_just_modules:
					print_debug_userstack(tag, ("line {0}: for ip {1}, found "
						"containing vma: {2}").format(linenum,
						hex(ip), vma.to_str_maps_format()))
				if vma.perms_key != 'r-xpf':
					# other combinations like 'r-xpa', maybe 'rwxpa',
					# 'r-xsf', etc. may be valid too - investigate
					# them when they appear and change this assertion.
					#   Just check if vma.perms_key[2] == 'x'?
					print_warning(tag, ("line {0} unexpected: ip "
						"is in a memory region with perms_key={1}, "
						"rather than r-xpf: {2}").format(linenum,
						vma.perms_key, vma.to_str_maps_format()))
					stack_proc_info.add_to_stats(
						'non-r-xpf-stackentries', 1)

				# For executable, file-backed mappings, we determine
				# the module from the mapping's filename. For 
				# anonymous mappings, we try to use the mapping's
				# "creator" field, which hopefully has been initialized
				# but may be UNKNOWN_MODULE.
				if vma.perms_key[4] == 'f':
					entrymodule = vma.filename
					if not debug_just_modules:
						print_debug_userstack(tag, ("line {0}: using filename "
							"as entrymodule: {1}").format(
							linenum, entrymodule))
					
					# For file-backed vmas, we can try to use the
					# userstacktrace ip and the filename to determine
					# the function that contains the ip: the function
					# names are usually retained within the executable /
					# shared object file, and can be seen when it is
					# disassembled ("objdump -d") or can be seen using
					# a binutils tool like addr2line or nm. Fortunately,
					# the vma.filenames are always absolute paths, so
					# as long as we're running the analysis on the same
					# system as the trace, we should be able to find the
					# executable / object file.
					#
					# The options/sym-userobj kernel tracing option enables
					# related, but not as useful functionality. When this
					# option is on, the kernel will attempt to look up
					# the ips in the userstacktrace in the process/task's
					# memory map, BUT this lookup is only performed at
					# trace output time (not trace capture time) - this
					# means that if the process/task has terminated, then
					# the lookup will fail. Additionally, the kernel will
					# only print the module / filename when the lookup is
					# successful; it will not try to dig down to the
					# function level. Since we're tracking the process'
					# memory map as we scan through the trace events file
					# anyway, we can perform the lookup just as well on
					# our own, and we don't have to worry about trying to
					# do it while the process is still running.
					#
					# Only do the function lookup if the user specified
					# to on the command-line, since it could be expensive.
					if ip_to_fn:
						print_debug_userstack(tag, ("looking up function that "
							"contains ip {} in file {}").format(
							hex(ip), entrymodule))
						entryfn = ip_to_fn.lookup(entrymodule, ip,
								vma.start_addr)
						if entryfn is None:
							# Never hit in simple hello-world trace.
							entryfn = FN_LOOKUPERR
							print_error(tag, ("ip_to_fn.lookup() error, "
								"using entryfn={}").format(entryfn))
						elif entryfn == '':
							# Hit 2972 times in simple hello-world trace.
							entryfn = FN_LOOKUPFAIL
							print_debug_userstack(tag, ("ip_to_fn.lookup() "
								"failed, using entryfn={}").format(entryfn))
						else:
							# Hit 2926 times in simple hello-world trace.
							print_debug_userstack(tag, ("ip_to_fn.lookup() "
								"succeeded, got entryfn={}").format(entryfn))
					else:
						entryfn = FN_DISABLED

				else:
					'''
					entrymodule = vma.creator_module
					# xxx: change this to a debug statement if/when hit.
					print_error_exit(tag, ("line {0}: anonymous mapping: "
						"using vma.creator_module as entrymodule, "
						"{1}").format(linenum, entrymodule))
					'''
					(entrymodule, entryfn) = (MODULE_ANON, FN_ANON)
					print_warning(tag, ("line {}: ip in an anonymous "
						"mapping, using entrymodule={}, entryfn={}").format(
						linenum, entrymodule, entryfn))
					stack_proc_info.add_to_stats(
						'anon-stackentries', 1)

			else:   # vma not found:
				(entrymodule, entryfn) = (MODULE_KERNEL, FN_KERNEL)
				if ip == firstexec_ip:
					# it doesn't really matter what entrymodule is used
					# in this case - a "reset_sim" event is about to come
					# anyway.
					print_debug_userstack(tag, ("line {0}: didn't find any "
						"vma that contains ip {1} for process "
						"{2}-{3}, but firstexec_ip matches this "
						"ip - we're in the middle of an exec, so "
						"the ip in the stack trace is meaningless. "
						"This trace event will be attributed to the "
						"kernel: module {4}, fn {5}".format(linenum, hex(ip),
						stack_proc_info.progname, stack_proc_info.pid,
						entrymodule, entryfn)))
				elif not stack_proc_info.have_full_info():
					(entrymodule, entryfn) = (UNKNOWN_MODULE, UNKNOWN_FN)
					print_debug_userstack(tag, ("line {0}: didn't find "
						"any vma that contains ip {1} for process "
						"{2}-{3}, but we don't have full information "
						"for this process, "
						"so we probably don't care about it. This "
						"event will be attributed to entrymodule="
						"{4}, entryfn={5}".format(linenum, hex(ip),
						stack_proc_info.progname, stack_proc_info.pid,
						entrymodule, entryfn)))
				else:
					#print_error_exit(tag, ("line {0}: didn't find "
					if firstexec_ip:
						fip_hex = hex(firstexec_ip)
					else:
						fip_hex = None
					print_warning(tag, ("line {0}: didn't find "
						"any vma that contains ip {1} for process "
						"{2}-{3} (and firstexec_ip={4})".format(
						linenum, hex(ip), stack_proc_info.progname,
						stack_proc_info.pid, fip_hex)))
					(entrymodule, entryfn) = (UNKNOWN_MODULE, UNKNOWN_FN)
					stack_proc_info.add_to_stats(
						'vma-not-found-for-stackentry', 1)

			if debug_just_modules: # or True:
				print(("@\t\t<{0}> ==> {1} ^ {2}").format(
					hex(ip)[2:].zfill(16), entrymodule, entryfn))

			# Ok, here's the tricky part: in order to properly
			# "attribute" vma operations to various modules, we need
			# to "interpret" the entire userstack trace and decide
			# which module to use. We probably don't want to use
			# just the "top" entry, because it will almost always
			# be libc or libstdc++ or whatever library wraps mmap
			# and the other memory-related system calls.
			#
			# One idea: actually track all of the modules involved
			# in the call?
			if entrymodule is None or entryfn is None:
				print_error_exit(tag, ("expect both entrymodule {} and "
					"entryfn {} to be set to some string at this "
					"point!").format(entrymodule, entryfn))
			#m = entrymodule.rsplit('/', 1)[1]
			homedir = '/home/pjh/research/virtual/'
			m = os.path.basename(entrymodule)
			if (entrymodule != MODULE_KERNEL and
					entrymodule != UNKNOWN_MODULE and
					entrymodule != MODULE_ANON and
					homedir not in entrymodule):
				# If the module's path doesn't contain my home directory,
				# then the library is being gotten from /usr/lib/* or
				# /lib/* or some other directory - this means that the
				# userstacktrace is unlikely to be able to unwind past
				# this point. Prepend a special tag so this will be visible
				# in the output...
				m = badtrace_str + m
			usermodule.append(m)   # list of modules from userstacktrace so far

			# Actually, it's easier to interpret the function if we always
			# include the module name in front of it.
			#   To see all userstacktrace fn results: egrep "\-\-\-\->"
			#   in debug output.
			fn = m + mod_fn_sep + entryfn
			userfn.append(fn)
			print_debug_userstack(tag, ("\n{} ----> {}").format(
				hex_zfill(ip), fn))

			continue

		stack_begin_match = userstacktrace_begin_re.match(line)
		if stack_begin_match:
			if stack_proc_info:
				print_error_exit(tag, ("hit a userstacktrace-begin "
					"line, but we've already gotten the proc_info "
					"in this method - did we really jump from one "
					"userstacktrace on this cpu immediately to the "
					"next? linenum={0}").format(linenum))
			print_debug_userstack(tag, ("hit an expected userstacktrace "
				"begin line {0} for cpu {1}").format(linenum, line_cpu))
			stack_task = stack_begin_match.group('task')
			stack_pid  = int(stack_begin_match.group('pid'))
			stack_tgid = int(stack_begin_match.group('tgid'))
			if event_task != stack_task:
				print_error_exit(tag, ("line {0}: task of stack_begin "
					"{1} doesn't match event_task {2}").format(linenum,
					stack_task, event_task))

			# Ok, this is a little weird: there are three cases:
			#   1) During a fork, the proc_tgid will be set to the
			#      child's pid, and the stack_tgid will be the parent's
			#      pid (note: the stack_pid could be a *thread* pid!).
			#      So, we want the stack_proc_info to be retrieved
			#      using the parent's tgid, stack_tgid.
			#   2) During single-threaded execution, the proc_tgid will
			#      be set to the process' pid==tgid, and the stack_pid
			#      will be the process' pid==tgid as well. So, we can
			#      retrieve the stack_proc_info using either tgid
			#      or stack_tgid.
			#   3) During multi-threaded execution, the proc_tgid will
			#      always be set to the top-level process pid, but the
			#      stack_pid will currently be set to the *thread's*
			#      pid, which will not match tgid. So, we want to
			#      use the tgid to get the stack_proc_info.
			#   How can we differentiate case 1 from case 3? In case 1,
			#   the pid and tgid from the original event (passed in to
			#   this method) will match; in case 3, they will not!
			proc_info_pid = None
			if mmap_pid and mmap_pid == proc_tgid:   # case 1 or 2
				proc_info_pid = stack_tgid
				print_debug_userstack(tag, ("line {}: using stack_tgid as "
					"proc_info_pid: {}").format(linenum, proc_info_pid))
				if DEBUG:
					'''
					# Hit this once during affiliates-data/firefox
					# analysis...
					if stack_tgid != stack_pid:
						print_error_exit(tag, ("cool: hit a case where "
							"a child *thread* is forking a new *process*! "
							"stack_pid={}, stack_tgid={}").format(
							stack_pid, stack_tgid))
					'''
			else:   # case 3
				proc_info_pid = proc_tgid
				if proc_tgid != stack_tgid:
					print_unexpected(tag, ("multi-threaded case: "
						"expect proc_tgid={} to equal stack_tgid="
						"{}").format(proc_tgid, stack_tgid))
				print_debug_userstack(tag, ("line {}: using proc_tgid == "
					"stack_tgid as proc_info_pid: {}").format(
					linenum, proc_info_pid))

			stack_proc_info = proc_tracker.get_process_info(proc_info_pid)
			if not stack_proc_info:
				# This may be expected: e.g. if we get a trace event like
				#   bash-2953 mmap_vma_alloc: pid=10084 tgid=10084 [dup_mmap]
				# If this is the first trace event for bash-2953, then we're
				# not going to have a proc_info for it yet, but the stack
				# trace that follows this event will still be for bash. In
				# this case we don't really care about the stack trace
				# and we can attribute the operation to kernel setup /
				# teardown. This operation is probably going to be
				# "sim_reset"-ted later anyway.
				if is_fork_event:
					# Append just one module/fn to usermodule and userfn,
					# then break out of loop without processing the rest
					# of the stack trace:
					entrymodule = MODULE_KERNEL
					entryfn = entrymodule + mod_fn_sep + FN_KERNEL
					print_debug_userstack(tag, ("line {0}: no proc_info found "
						"already for proc_info_pid {1}, but "
						"is_fork_event is True, so count this towards "
						"{2} module and function {3}").format(
						linenum, proc_info_pid, entrymodule, entryfn))
					usermodule.append(entrymodule)
					userfn.append(entryfn)
					print_debug_userstack(tag, ("\n{} ----> {}").format(
						"fork", entryfn))
					break
				else:
					print_error_exit(tag, ("line {0}: expect to have "
						"a proc_info for proc_info_pid {1} by now - "
						"is_fork_event is False").format(linenum,
						proc_info_pid))
			
			'''
			# Ok, now that we have the proc_info for the correct process
			# that's "responsible" for this user stack trace, the last
			# thing that we do is check if this process is part of a
			# multiprocess group and has a tgid_for_stats that differs
			# from its actual tgid; if so, we re-set the stack_proc_info
			# to find the
			  NEVERMIND - the vmas will still be tracked on a per-process
			  basis!
			'''
			stack_proc_context = stack_proc_info.get_context()
			continue

		stack_reason_match = userstacktrace_reason_re.match(line)
		if stack_reason_match:
			reason = stack_reason_match.group('reason')
			print_debug_userstack(tag, ("reason that stack unwind stopped for "
				"process {}-{}: {}").format(
				event_task, proc_info_pid, reason))
			continue

		# If we reach here and haven't explicitly continued the loop
		# yet, then break:
		print_debug_userstack(tag, ("hit next line {0} for cpu {1} "
			"that's not a userstacktrace line - this method is "
			"done").format(linenum, event_cpu))
		break

	if len(usermodule) != len(userfn):
		print_error_exit(tag, ("assert failed: length of usermodule {} "
			"doesn't match length of userfn {}").format(usermodule, userfn))
	if len(usermodule) > 0:
		print_debug_userstack(tag, ("\n\t---->").format())   # debug separator
	usermodule = compress_userstack_modules(usermodule, debug_just_modules)
	userfn = compress_userstack_fns(userfn)
	if DEBUG and userfn and reason:
		userfn += ">{}".format(reason)
		print_debug_userstack(tag, ("process {}-{}: reason: {}").format(
			event_task, proc_info_pid, userfn))

	trace_f.seek(original_pos)   # don't forget!
	#print_debug_userstack(tag, ("last processed line was {0}").format(
	#	linenum))
	#print_debug_userstack(tag, ("ip_to_fn.lookup():"))   # debug separator...

	return (usermodule, userfn)

# When a fork event is encountered, this method will look ahead in the
# trace events file to see if the fork will be followed by an exec.
# If the fork is just going to be exec'd anyway, then we may wish to
# just skip the trace events - this will be much easier than trying to
# "undo" any fork events that we accounted for when the exec is
# encountered. This method should be called exactly when the
# first fork event ('dup_mmap') is encountered for a new proc_info.
# 
# Arguments: the open trace file, the current line number (just for debug
# output), and the vma_event_re match object for the current line.
#   
# Returns: True if the events following the fork indicate that an exec
# also occurred, False if there is no exec (or if EOF was reached while
# we looked ahead).
def lookahead_fork_exec(trace_f, linenum, fork_vma_match):
	tag = "lookahead_fork_exec"

	if not fork_vma_match:
		print_error_exit(tag, ("fork_vma_match is None, but it should "
			"always be valid if we know we're on the first fork "
			"event").format())
	if fork_vma_match.group('fn_label') != 'dup_mmap':
		print_error_exit(tag, ("expect current fork_vma_match to be for "
			"dup_mmap, but fn_label = {}").format(fork_vma_match.group(
			fn_label)))

	fork_pid = int(fork_vma_match.group('pid'))
	fork_tgid = int(fork_vma_match.group('tgid'))
	if (fork_pid != fork_tgid):
		print_error_exit(tag, ("fork event: expect fork_pid {} to match "
			"fork_tgid {}").format(fork_pid, fork_tgid))

	original_pos = trace_f.tell()
	found_exec = False
	print_debug(tag, ("looking ahead from line {}").format(linenum))

	while True:
		line = trace_f.readline()
		linenum += 1
		if not line:
			print_warning(tag, ("hit EOF while looking ahead for exec "
				"events - this is sometimes expected, right?").format())
			break
		if line[0] == '#':   # skip comment lines
			continue

		# What do we need to know to check if the current fork event
		# is followed by an exec? We just need to find the next event
		# that's NOT a fork (dup_mmap) event for this pid / tgid (I
		# think the pid should be the same as the tgid because we're
		# forking a new process - right?). If the very next event is
		# an exec event (__bprm_mm_init), then we'll return True; if
		# the very next event is anything else, then we'll return
		# False. I wrote a little test program for a fork without an
		# exec, and confirmed that this all makes sense.
		#   Note: skip over physical page events ("pte" events) that
		#   I added later - this logic is just for mmap_* trace
		#   events.
		#
		# What if the first event for the forked process is an
		# exit_mmap - the forked process doesn't actually do anything
		# "of substance" that allocates other vmas? Well, if we assume
		# that the forked process did *something* (even if it didn't
		# cause any vma operations), then it did that something using
		# the code+data in the duplicated mmap, so we want to include
		# its initial dup_mmap events in our analysis - we'll return
		# found_exec = False from here.
		#
		# Unlike in process_userstack_events (the other lookahead
		# method that we use), we don't care about the CPU that the
		# events are emitted from.
		event_match = trace_event_re.match(line)
		if not event_match:
			#print_debug(tag, ("skipping non-trace-event line {}").format(
			#	linenum))
			continue
		trace_event = event_match.group('trace_event')
		if not re.compile(r'^mmap_').match(trace_event):
			#print_debug(tag, ("skipping trace_event {} that's not "
			#	"an mmap_* event that we care about for this "
			#	"method").format(trace_event))
			continue

		event_msg = event_match.group('event_msg')
		vma_match = vma_event_re.match(event_msg)
		if not vma_match:
			#print_debug(tag, ("skipping non-mmap_vma event line "
			#	"{}").format(linenum))
			continue

		match_pid   = int(vma_match.group('pid'))
		match_tgid  = int(vma_match.group('tgid'))
		match_ptgid = int(vma_match.group('ptgid'))
		if match_pid == fork_pid:
			if match_pid != match_tgid:
				# I think this is unexpected...
				print_error_exit(tag, ("match_pid {} matches fork_pid {} "
					"but not match_tgid {}!?").format(match_pid,
					fork_pid, match_tgid))
			match_fn = vma_match.group('fn_label')
			if match_fn == 'dup_mmap':
				#print_debug(tag, ("looking beyond subsequent fork line "
				#	"{}").format(linenum))
				continue
			elif match_fn == '__bprm_mm_init':
				found_exec = True
				print_debug(tag, ("first mmap_vma_* event after fork "
					"events for pid {} is {} for exec (line {}); "
					"returning found_exec={}").format(match_pid, match_fn,
					linenum, found_exec))
				break
			else:
				found_exec = False
				print_debug(tag, ("first mmap_vma_* event after fork "
					"events for pid {} is {} (line {}) - not an exec "
					"event, so returning found_exec={}").format(match_pid,
					match_fn, linenum, found_exec))
				break
			print_error_exit(tag, "unreachable")
		elif match_ptgid == fork_pid:
			# During a kernelbuild trace I encountered this case: a
			# forked process did another fork as its very first action,
			# so the trace events emitted by the first forked process
			# ended up with the pid/tgid of the child, and the lookahead
			# has to look really far to find the first trace event
			# that's not a dup_mmap of another child. To optimize this,
			# we *could* assume here that the first forked process is
			# not going to exec since it already performed another fork,
			# but this might not always be the case...
			#   Well, even if an exec does follow later, this process
			#   has used its duplicated mmap to perform at least one
			#   action (another fork), so we want to account for the
			#   duplicated mmap in our analysis - return found_exec
			#   = False.
			#
			# I think I encountered this again in my apache trace, where
			# I found this sequence of events:
			#   apache2-6470: mmap_vma_alloc_dup_mmap:
			#     pid=6473 tgid=6473 ptgid=6470 [dup_mmap] ...
			#   (repeat...)
			#   grep-6473: mmap_vma_alloc_dup_mmap:
			#     pid=6474 tgid=6474 ptgid=6473 [dup_mmap]
			#   cat-6474: mmap_vma_alloc:
			#     pid=6474 tgid=6474 ptgid=6473 [__bprm_mm_init]
			#   grep-6473: mmap_vma_alloc:
			#     pid=6473 tgid=6473 ptgid=6470 [__bprm_mm_init]
			# What the hell?? Why/how can grep fork off cat before it has
			# performed its own exec??? I'm so confused :(
			found_exec = False
			print_debug(tag, ("got an mmap_vma_* event for a different "
				"pid {}, but its ptgid {} matches the forked process "
				"we're looking ahead for - so we want to include {}'s "
				"fork events in our analysis, return found_exec={} "
				"(line {})").format(match_pid, match_ptgid,
				match_ptgid, found_exec, linenum))
			if vma_match.group('fn_label') != 'dup_mmap':
				print_unexpected(False, tag, ("but mmap_vma_* event "
					"does not come from dup_mmap, as expected: "
					"{}").format(vma_match.group('fn_label')))
			break
		else:
			#print_debug(tag, ("skipping line {} for some other pid "
			#	"{}").format(linenum, match_pid))
			continue

	trace_f.seek(original_pos)   # don't forget!

	return found_exec

# The usermodule_list argument should be the FULL list of modules that
# were encountered during the userstacktrace events, with the "top" of
# the userstack (the first trace line encountered) at the beginning
# of the list. This function will take care of reversing the list,
# eliminating duplicates, and so on.
# This function will return a string that should be used to represent
# the usermodule, or will return None if the usermodule_list is empty.
def compress_userstack_modules(usermodule_list, debug_just_modules):
	tag = 'compress_userstack_modules'
	global module_sep

	if len(usermodule_list) == 0:
		return None
	if not debug_just_modules:
		print_debug(tag, ("len(usermodule_list): {0}").format(
			len(usermodule_list)))

	rev = reversed(usermodule_list)
	compressed = []

	# One way to construct "compressed" string: start from the bottom
	# of the stack, then go forward, eliminating duplicates. This way,
	# whatever is at the very top of the userstacktrace (arguably the
	# most important module, that we likely want to "attribute" the
	# kernel event to) will appear last (right?) in the string.
	for module in rev:
		if module not in compressed:
			compressed.append(module)
	
	string = module_sep.join(compressed)

	return string

# The userfn_list argument should be the FULL list of functions that
# were encountered during the userstacktrace events, with the "top" of
# the userstack (the first trace line encountered, and the most-recent
# call) at the beginning of the list. This function will take care of
# reversing the list, eliminating duplicates, and so on.
# This function will return a string that should be used to represent
# the userfn, or will return None if the userfn_list is empty.
def compress_userstack_fns(userfn_list):
	tag = 'compress_userstack_fns'
	global fn_sep

	if len(userfn_list) == 0:
		return None
	'''
	print_debug(tag, ("len(userfn_list): {0}").format(
		len(userfn_list)))

	rev = reversed(userfn_list)
	compressed = []

	# One way to construct "compressed" string: start from the bottom
	# of the stack, then go forward, eliminating duplicates. This way,
	# whatever is at the very top of the userstacktrace (arguably the
	# most important fn, that we likely want to "attribute" the
	# kernel event to) will appear last (right?) in the string.
	for fn in rev:
		if fn not in compressed:
			compressed.append(fn)
	
	string = fn_sep.join(compressed)

	return string
	'''

	#print_debug(tag, ("got userfn_list: {}").format(userfn_list))
	#fn_string = userfn_list[0]
	#print_debug(tag, ("for now, choosing fn at top of stack: {}").format(
	#	fn_string))

	# Keep the full set of functions, just append them all together:
	rev = reversed(userfn_list)
	fn_string = fn_sep.join(rev)

	print_debug(tag, ("----> creator_fn: {}").format(fn_string))
	return fn_string

def determine_component_query_fn(vma):
	component = determine_component(vma)
	return [component]

# This method will examine the creator_module of the given vma, which
# will have been set by compress_userstack_modules(), and will return
# a list of "categories" that the vma belongs to.
def sophisticated_module_query_fn(vma):
	tag = 'sophisticated_module_query_fn'
	global MODULE_KERNEL
	global MODULE_ANON
	global module_sep
	global badtrace_str

	keylist = []
	modstr = vma.creator_module
	modlist = modstr.split(module_sep)
	creator_fn = vma.creator_fn

	#keylist.append(modstr)

	# How many traces is kernel responsible for?
	# I wasn't sure if this was working or not, but I think that it's
	# not unexpected for a target app to not have any kernel vma
	# operations, since these only happen during a fork (right?) and
	# then a reset-sim event is emitted...
	#   Then check: why are they emitted for all_cpus?
	#print_error_exit(tag, ("need to investigate: why does all_cpus "
	#	"have kernel events, but not firefox or graph500??").format())
	if MODULE_KERNEL in modstr:
		#print_debug(tag, ("{} in {}").format(MODULE_KERNEL,
		#	modstr))
		keylist.append(MODULE_KERNEL)  # is this working?
	if 'kernel(setup-teardown)' in modstr:
		keylist.append('kernel2')
	if 'teardown' in modstr:
		keylist.append('kernel3')

	# How many traces end in ld-?
	if lib_ld_re.search(modlist[-1]):
		#print_debug(tag, ("found ld-[\d.]+\.so in {}").format(
		#	modlist[-1]))
		keylist.append('ends-in-ld')
		if len(modlist) == 1:
			keylist.append('just-ld')

	targetapp = 'firefox'   # HACK alert!

	# How many traces include ld?
	#   (note: I checked and whenever libdl is used, it’s followed by ld-)
	#   How many of these do / do not include firefox?
	if lib_ld_re.search(modstr):
		#print_debug(tag, ("found ld-[\d.]+\.so in {}").format(
		#	modstr))
		keylist.append('contains-ld')
	if lib_ld_re.search(modstr) and targetapp not in modstr:
		keylist.append("contains-ld-but-not-{}".format(targetapp))
	
	if 'libc-2.17.so' in modstr:
		keylist.append("contains-libc-2.17")

	# How many traces include firefox?
	#   How many do not? [and how can this be??]
	# How many traces end in firefox?
	if targetapp in modstr:
		keylist.append("contains-{}".format(targetapp))
	else:
		keylist.append("no-{}-how-can-this-be?".format(targetapp))
	if targetapp in modlist[-1]:
		keylist.append("ends-in-{}".format(targetapp))

	# How many traces are bad traces: begin in ‘USR’
	if badtrace_str in modstr:
		keylist.append('BAD-TRACE-UNWIND')
	
	# How many traces include unknown_module? anon-mapping?
	if MODULE_KERNEL in modstr:
		keylist.append('trace-hits-unknown-module')
	if MODULE_ANON in modstr:
		keylist.append('trace-hits-anon-mapping')
	
	keylist.append("begins-with-{}".format(modlist[0]))
	if len(modlist) == 1:
		keylist.append("just-{}".format(modlist[0]))

	# App / library-level memory allocation?
	#   This isn't quite right yet because it will include pure-ld and
	#   pure-libc stacks that include calls to malloc - should also
	#   check for target process name here.
	#if 'malloc' in creator_fn:
	if 'libc_malloc' in creator_fn:
		keylist.append('fn-contains-libc_malloc')
	if 'alloc' in creator_fn:
		keylist.append('fn-contains-alloc')

	return keylist

def lazy_module_query_fn(vma):
	return [vma.creator_module]

def lazy_fn_query_fn(vma):
	return [vma.creator_fn]

# Returns True if the vma_match was successful and the 'fn_label' (the
# internal kernel function emitting the trace event) contains one of
# the set of labels that indicate fork events defined below.
def is_fork_event(vma_match):
	fork_fn_labels = ['dup_mmap']
	if vma_match:
		for fn in fork_fn_labels:
			if fn in vma_match.group('fn_label'):
				# 1/6/14: for new "mmap_vma_alloc_dup_mmap" event,
				# fn_label will still be dup_mmap, so this should
				# still work correctly.
				return True
	return False

# Similar to is_fork_event(). If just_first_exec is true, then this
# function will only look for a match the first-known trace event that
# happens during an exec ('__bprm_mm_init').
def is_definitely_exec_event(trace_event, vma_match, just_first_exec):
	# First, examine the trace_event - during execs, we emit our own
	# special event:
	if not just_first_exec:
		exec_event_labels = ['mmap_reset_sim']
		for event in exec_event_labels:
			if event in trace_event:
				print_error_exit(tag, ("no longer expect to see this "
					"event type: mmap_reset_sim").format())
				return True

	# There are other fn_labels that are seen during the process
	# exec, before control returns to the process and it moves
	# beyond its "firstexec ip", but they are also seen at other
	# times: e.g. __split_vma, mmap_region, do_brk, .... The
	# fn_labels below are *only* seen during an exec, I think.
	if just_first_exec:
		exec_fn_labels = ['__bprm_mm_init']
	else:
		exec_fn_labels = ['__bprm_mm_init', 'expand_downwards',
			'exit_mmap', 'load_elf_binary', 'shift_arg_pages',
			'setup_arg_pages']
		  # vmware-vmx: mprotect_fixup may occur during exec (just after
		  # exit_mmap) too...
	if vma_match:
		for fn in exec_fn_labels:
			if fn in vma_match.group('fn_label'):
				return True
	
	return False

def is_exit_event(vma_match):
	exit_fn_labels = ['exit_mmap -> remove_vma']
	if vma_match:
		for fn in exit_fn_labels:
			if fn in vma_match.group('fn_label'):
				return True
	return False

# event_match: comes from trace_event_re.
# Returns: a PlotEvent object.
def handle_trace_marker(event_match, proc_tracker, outputdir,
		group_multiproc, target_pids, current_appname):
	tag = 'handle_trace_mark'

	# Plan for this method:
	#   Every time that a trace_marker event is encountered, consider
	#   it to be a "checkpoint": we want to write out the current
	#   analysis state, then reset some of the analysis state so that
	#   when we hit the next checkpoint we can write out the state
	#   since the previous checkpoint. To support this, we can use
	#   the "cp_vmas" member that has been added to each process_info,
	#   which contains all of the vmas that have been modified since
	#   the last reset.
	#
	# Trace marker events look like this:
	#   bash-11809 [001] ...1 171543.734505: tracing_mark_write: abracadabra
	# Note that the task / pid writing the message is probably one that
	# we don't really care about; for now, we'll just execute a checkpoint
	# for _every_ process, but eventually this could be enhanced by
	# parsing the event_msg valid for a target-pid. This is not particularly
	# reliable either at the moment, because the pid from the event itself
	# could be a thread pid and not the tgid that we really want; the
	# solution would be to explicitly grab the tgid when the
	# tracing_mark_write event is recorded in the kernel.

	# Parse the event:
	kernel_timestamp = float(event_match.group('timestamp'))
	trace_event = event_match.group('trace_event')
	event_msg = event_match.group('event_msg')
	if trace_event != 'tracing_mark_write':
		print_error_exit(tag, ("unexpected: got trace_event {0}").format(
			trace_event))
	cp_name = sanitize_fname(event_msg, spaces_ok=False)
	cp_dir = "{}/{}".format(outputdir, cp_name)
	try:
		os.mkdir(cp_dir)
	except OSError:
		# Right now, this happens for Mediawiki traces because we
		# visit the same page (Special:Random) several times...
		print_warning(tag, ("checkpoint directory with name "
			"{} already exists! Will delete it and re-create it").format(
			cp_dir))   # probably ok...
		shutil.rmtree(cp_dir)
		os.mkdir(cp_dir)
	print_debug(tag, ("using cp_name \"{0}\" as checkpoint name").format(
		cp_name))

	# Write output: we want some items / queries to use cp_vmas to see
	# what was performed since the previous checkpoint, but for other
	# items / queries we want to see the current global state (e.g.
	# vmatable). So, we can just call run_queries twice: once for
	# the "checkpoint" queries, and once for the "current" queries.
	for querytype in ['checkpoint', 'current']:
		print_debug(tag, ("at checkpoint, calling queries of type "
			"{}").format(querytype))
		run_queries(cp_dir, proc_tracker, querytype, group_multiproc,
			target_pids)

	# Reset the cp_vmas:
	for proc_info in proc_tracker.get_all_process_infos():
		proc_info.reset_sim_data('cp')

	# Create a plot event:
	cp_event = CheckpointEvent(kernel_timestamp, current_appname, cp_name)
	plot_event = PlotEvent(cp_event=cp_event)

	return plot_event

# Arguments: mmap_match object for the current trace event, the
# processes_tracker, child tgid, child's proc_info object, and
# bool for whether or not to group child processes with parent.
# Gets the process_info object for the child and sets its ptgid field
# to the parent. Additionally, if the group_multiproc arg is
# True, traces up the process hierarchy formed
# by the ptgid fields in the proc_infos and determines the "root"
# process that this child's memory stats should be attributed to.
# If group_multiproc is False, then stats will always be attributed
# to each process and children will not be grouped together with their
# parents (note that *thread* events will always be grouped with their
# parent tgids).
# This method is intended to be called just once, when a fork creates
# a new child process with a new tgid.
#   Update: or when an exec is seen for a new tgid that skipped the
#   dup_mmap part of the fork (e.g. 'make' during a kernel build).
#     <...>-5511  [000] ....  5147.967813: mmap_vma_alloc: pid=5511 tgid=5511 ptgid=3757 [__bprm_mm_init]: ffff8800741a10b8 @ 7ffffffff000-7ffffffff000 rw-p 00000000 00:00 0
def handle_multiproc(vma_match, proc_tracker, ctgid, child_proc_info,
		group_multiproc, target_pids):
	tag = 'handle_multiproc'

	def print_hierarchy(level, msg):
		if False:
			if not msg or len(msg) < 2:
				print('HIERARCHY: -----------------------')
			else:
				ls = '+' + ('--' * level)
				print('HIERARCHY: {} {}'.format(ls, msg))

	child = child_proc_info
	ptgid = int(vma_match.group('ptgid'))  # parent's tgid
	event_tgid = int(vma_match.group('tgid'))
	if event_tgid != ctgid:
		print_unexpected(True, tag, ("child tgid arg {} doesn't "
			"match tgid from trace event {} - we always expect it to "
			"in this method (called only when is_fork_event() is "
			"true)").format(ctgid, event_tgid))

	child.set_ptgid(ptgid)
	print_debug(tag, ("for process {}, set parent's tgid "
		"ptgid={}").format(child.name(), child.get_ptgid()))

	# Apps like apache and chrome fork child processes that don't exec.
	# For these processes, we may want to process events (i.e. dup_mmap
	# events during the fork) before the child process' program name
	# has actually been set. So, in these cases, set a "speculative"
	# program name that is actually the parent's progname, which we
	# can use for e.g. plot events for now. Later, when we actually
	# set this process' progname, check against the speculative progname
	# and raise an error if they don't match.
	if is_fork_event(vma_match) and child.exec_follows_fork is False:
		parent = proc_tracker.get_process_info(ptgid)
		if not parent or not parent.is_progname_set():
			# This may happen e.g. if a cron job starts while our trace
			# was running; shouldn't happen for processes that we care
			# about, I think. I'm not sure I need the "speculative
			# progname" anymore anyway...
			print_unexpected(False, tag, ("fork event for child and "
				"no exec to follow - we should always have a parent "
				"proc_info at this point, right? ptgid={}, parent="
				"{}").format(ptgid, parent))
		else:
			child.set_speculative_progname(parent.progname)
			print_debug(tag, ("special fork-no-exec case: set child {}'s "
				"speculative_progname to {}").format(child.pid,
				child.speculative_progname))

	if group_multiproc:
		# Trace up the process hierarchy and decide whether this process
		# should be a "root" process, or find the appropriate root process
		# for this child process. A root process is one that has a
		# parent that we have NOT seen a fork for (meaning that parent
		# process was already running when the trace began), but that
		# has had a fork event itself.
		print_hierarchy(0, child.name())
		level = 1
		parent = proc_tracker.get_process_info(ptgid)
		if not parent:
			print_debug(tag, ("no proc_info exists for {}'s parent "
				"{}, so {} is a root!").format(
				child.name(), ptgid, child.name()))
			child.set_is_rootproc(True)
			child.set_tgid_for_stats(ctgid)
		elif parent.get_ptgid() is None:
			print_debug(tag, ("parent {} has no ptgid, so child "
				"{} is a top-level process started during this "
				"trace - it is a root").format(parent.name(),
				child.name()))
			child.set_is_rootproc(True)
			child.set_tgid_for_stats(ctgid)
		else:
			# parent is valid and itself has a parent - trace up until
			# we hit a root!
			print_debug(tag, ("looking up hierarchy, starting from {}'s "
				"parent {}").format(child.name(), parent.name()))
			while not parent.get_is_rootproc():
				parent_ptgid = parent.get_ptgid()
				if not parent_ptgid:
					print_unexpected(True, tag, ("parent_ptgid is None, "
						"unexpected at this point!").format())
				parent = proc_tracker.get_process_info(parent_ptgid)
				if not parent:
					print_unexpected(True, tag, ("no process_info found "
						"for parent_ptgid {} - unexpected at this "
						"point, should have a complete hierarchy").format(
						parent_ptgid))
				print_debug(tag, ("moved up hierarchy to parent "
					"{}").format(parent.name()))
				print_hierarchy(level, parent.name())
				level += 1
			if not child.get_pid() in target_pids:
				# This is the original / "usual" case. Importantly,
				# we don't stop the search up the hierarchy when we
				# hit a process that has already been set to be a root
				# process (not when we hit a process that doesn't have
				# a known parent's parent) - this matters for the Chrome
				# case described below.
				print_debug(tag, ("hit root process {}, will use this tgid "
					"for child {}'s stats and set it to be a non-root").format(
					parent.name(), child.name()))
				child.set_is_rootproc(False)
				child.set_tgid_for_stats(parent.get_pid())
			else:
				# This is the "abnormal" case, e.g. for automatic
				# execution of Chrome: the "root" process is the
				# chromedriver, but the process that we care about
				# (in the target_pids list) is the chrome process
				# that's a child of the chromedriver.
				# This also happens for apache: the "apache2" service
				# is started, and then the pidfile we use to get
				# target_pids actually contains the pid of an apache2
				# process that is forked off of the initial apache2.
				print_debug(tag, ("found a parent root process {} for "
					"child {}, but child's pid is in target_pids, so "
					"forcing child to be a rootproc and using its own "
					"pid as tgid_for_stats! (call this the "
					"\"chrome exception\")").format(parent.name(),
					child.name()))
				child.set_is_rootproc(True)
				child.set_tgid_for_stats(child.get_pid())

			# In the chrome case, this will cause the first chrome
			# process to be added to chromedriver's children list, and
			# then all subsequent grand- and grand-grand-children
			# will be added to the chrome process' children list.
			parent.add_child(child.get_pid())
			print_debug(tag, ("added child {} to parent "
				"{}'s list of children: {}").format(
				child.name(), parent.name(), parent.get_children_tgids()))
	else:
		child.set_is_rootproc(True)
		child.set_tgid_for_stats(ctgid)
		print_debug(tag, ("group_multiproc is False, so calling "
			"process {} a root process and set its tgid_for_stats = "
			"{}").format(child.name(), child.get_tgid_for_stats()))

	print_hierarchy(0, None)
	print_debug(tag, ("whew, done: for child {}, is_rootproc={} and "
		"tgid_for_stats={}").format(child.name(),
		child.get_is_rootproc(), child.get_tgid_for_stats()))
	return

# plot_event: A PlotEvent object. For mmap_* events, it contains 
#   the vma that was just mapped or unmapped by a call to
#   map_unmap_vma(), or None if the trace event unmapped a vma that
#   was not found or if the event is not a vma event (e.g.
#   tracing_mark_write). For pte_* or trace-mark events, it will
#   contain other data.
# plotlist: list of multiapp_plot objects that need to be made aware
#   of this event from the trace file.
# tgid_for_stats: tgid to use for accounting of this event, or -1
#   if this is a checkpoint event.
# ...
# Returns: nothing.
def handle_plot_event(plot_event, plotlist, event_tgid, target_pids,
		proc_tracker, group_multiproc, current_appname,
		tgid_for_stats, skip_irrelevant_processes):
	tag = 'handle_plot_event'

	if not plot_event:
		print_error(tag, ("plot_event is None"))
		#print_TODO(tag, ("modifiedvma is None, either means that "
		#	"map_unmap_vma() tried to unmap a vma that was not found "
		#	"in the vmatable (i.e. for a process we don't have full "
		#	"info for), or that this is a tracing_mark_write (checkpoint) "
		#	"event. Figure out how to handle checkpoints here!").format())
		return

	if plot_event.cp_event:
		if tgid_for_stats:
			print_unexpected(True, tag, ("got a cp_event, but "
				"expect tgid_for_stats to be None, not {}").format(
				tgid_for_stats))
		# Checkpoint events don't have an associated tgid.
		if (plot_event.vma or plot_event.page_event or
				plot_event.perf_sample):
			print_error_exit(tag, ("unexpected: when plot_event.cp_event "
				"set, vma={}, page_event={}, perf_sample={}").format(
				plot_event.vma, plot_event.page_event,
				plot_event.perf_sample))
	else:
		if skip_irrelevant_processes:
			if tgid_for_stats < 1:
				print_unexpected(True, tag, ("do_we_care() obsoleted "
					"by earlier is_relevant() call, but passed an "
					"unexpected tgid_for_stats {} here!").format(
					tgid_for_stats))
		else:
			# I wrote this code long ago, before adding the
			# skip_irrelevant_processes flag in process_trace_file;
			# so, when skip_irrelevant_processes is False, we must
			# still execute the code below in order to make the plots
			# work.
			# Determine if we care about this event, given the
			# specified tgid and target_pids list. tgid is from the
			# specific kernel / vma event. The tgid_for_stats that
			# is returned may be the same as the event_tgid, or it
			# may be the "root" process in a multiprocess hierarchy.
			if not target_pids or len(target_pids) == 0:
				print_warning(tag, ("target_pids is {}, so now just saying "
					"that we don't care - won't pass this vma/event to "
					"plots").format(target_pids))
				return
			skip_partial_processes = False
			tgid_for_stats = do_we_care(proc_tracker, group_multiproc,
					skip_partial_processes, target_pids, event_tgid)
			if not tgid_for_stats or tgid_for_stats < 1:
				#print_debug(tag, ("do_we_care() returned {}, so not passing "
				#	"this vma / event to plots").format(tgid_for_stats))
				return

	# Use the tgid_for_stats (which now comes from earlier call to 
	# is_relevant() when skip_irrelevant_processes is set) for proper
	# accounting of this event!
	for plot in plotlist:
		if tgid_for_stats:
			# Should we try to pull the appname for plotting from the
			# trace events themselves? I got this pretty much working
			# I think, but the problem is that the appname that we
			# want to show up in our plots (e.g. "apache") doesn't
			# always match the task names in the trace events file
			# (e.g. "apache2"). This not only messes up the plot text,
			# but also causes problems with checkpoints, e.g. because
			# the trace_marker_write events aren't associated with
			# the same (e.g. "apache2") task as the other events we
			# care about.
			#
			# So, for now, just use the appname that's passed down to
			# us as a top-level argument for this script. This will
			# be somewhat problematic if/when we try to extract plot
			# data for multiple different apps from the same trace,
			# but if we skip the checkpoint events (or somehow force
			# them to be associated with some task name that comes
			# from a proc_info below), then we could handle it.
			use_appname_from_trace = False
			if not use_appname_from_trace:
				# current_appname is a required argument for this
				# script (see argparsers.py: it may default to something
				# like 'app' if not provided, but it's never None).
				appname = current_appname
			else:
				proc_info = proc_tracker.get_process_info(tgid_for_stats)
				if proc_info:
					if proc_info.is_progname_set():
						appname = proc_info.progname
					elif proc_info.is_speculative_progname_set():
						# This may happen for e.g. apache and chrome: they
						# fork new processes that don't exec, so we *do*
						# care about those fork events, but the fork events
						# occur before we've set the progname for the new
						# proc_info. In this case, use their "speculative"
						# progname, and then check later when set_progname()
						# is called that we did the right thing here.
						appname = proc_info.speculative_progname
						#proc_info.set_speculative_progname_used()
						print_debug(tag, ("special fork-no-exec case: "
							"using speculative_progname {} as appname").format(
							appname))
					else:
						print_unexpected(True, tag, ("we don't have a "
							"progname or a speculative_progname for this "
							"event (tgid_for_stats={})").format(
							tgid_for_stats))
				else:
					print_unexpected(True, tag, ("get_process_info({}) "
						"failed").format(tgid_for_stats))
		else:
			# For CheckpointEvents, use the current_appname that has
			# been passed down from the very top-level of this script.
			appname = current_appname
		if PROCESS_INFO_UNKNOWN_NAME in appname:   #sanity check
			print_error_exit(tag, ("appname {} contains {} - this "
				"will lead to bad series being created and plotting "
				"won't work properly").format(appname,
				PROCESS_INFO_UNKNOWN_NAME))

		success = plot.consume_plot_event(plot_event, tgid_for_stats,
				appname)
		if not success:
			print_error_exit(tag, ("consume_vma failed for plot "
				"{}").format(plot.plotname))

	return

def reset_plots(proc_info):
	tag = 'reset_plots'

	print_error_exit(tag, ("don't use this yet").format())
	for plot in plotlist:
		plot.reset()

	return

def process_sched_trace_event(trace_event, event_match, cpu_tracker,
		proc_tracker):
	tag = 'process_sched_trace_event'

	cpu = int(event_match.group('cpu'))
	event_msg = event_match.group('event_msg')

	if trace_event == 'sched_switch':
		cpu_info = cpu_tracker.get_cpu_info(cpu)
		if not cpu_info:
			cpu_info = cpu_tracker.add_new_cpu(cpu)
			sched_match = sched_switch_event_re.match(event_msg)
		if not sched_match:
			print_error_exit(tag, ("got sched_switch event, but "
				"sched_match failed").format())
		prev_comm  = sched_match.group('prev_comm')
		prev_pid   = int(sched_match.group('prev_pid'))
		prev_tgid  = int(sched_match.group('prev_tgid'))
		prev_prio  = sched_match.group('prev_prio')
		prev_state = sched_match.group('prev_state')
		next_comm  = sched_match.group('next_comm')
		next_pid   = int(sched_match.group('next_pid'))
		next_tgid  = int(sched_match.group('next_tgid'))
		next_prio  = sched_match.group('next_prio')
		#print_debug(tag, ("sched_switch cpu {0}: prev {1}-{2} "
		#	"to next {3}-{4}").format(cpu,
		#	prev_comm, prev_pid,
		#	next_comm, next_pid))
	
		old_current_pid = cpu_info.set_current_pid(next_pid)
		if old_current_pid and old_current_pid != prev_pid:
			# This happens occasionally and blatantly (not as a
			# result of weird interleavings or anything); in a
			# firefox trace I've seen this, on lines 2337-2339:
			#      <...>-3419  [001] sched_switch: prev_tgid=3419
			#          ==> next_tgid=11809
			#   metacity-2722  [000] sched_switch: prev_tgid=2722
			#          ==> next_tgid=0
			#       bash-2993  [001] sched_switch: prev_tgid=2993
			#          ==> next_tgid=11769
			# What happened to 11809 on CPU 001? Actually, it never
			# appears again - maybe there was a sched_process_exit
			# event that I should capture, which would show that
			# pid 2993 got scheduled in next (through some other
			# path that doesn't emit a sched_switch event).
			#   What's the possible impact of this on my
			#   measurements? It won't matter for the process
			#   that exited ("old_current_pid"), since we're going
			#   to end its quantum here anyway. I think it
			#   shouldn't matter to the process that got scheduled
			#   in some other way (prev_pid) either, because we
			#   aren't currently starting each quantum explicitly
			#   (we aren't carefully tracking elapsed time / insns
			#   for each quantum); since each quantum is started
			#   implicitly, any vma events that happen after the
			#   "hidden" sched_switch will still be attributed
			#   appropriately to the "next" quantum for the
			#   prev_pid process.
			#strict_sched = False
			#print_unexpected(strict_sched, tag, ("missing a "
			print_debug(tag, ("missing a "
				"sched_switch event? old_current_pid={0}, but "
				"event's prev_pid={1}").format(old_current_pid,
				prev_pid))
			handle_sched_switch(old_current_pid, proc_tracker)
			handle_sched_switch(prev_pid, proc_tracker)
		else:
			# For the process / pid that we just swapped out: track
			# the number of vmas that were accessed during the
			# previous scheduling "quantum".
			handle_sched_switch(prev_pid, proc_tracker)
	elif trace_event == 'sched_process_fork':
		print_debug(tag, ("ignoring sched_process_fork event "
			"for now").format())
	else:
		print_error_exit(tag, ("unexpected sched event "
			"{}").format(trace_event))

	return

# Handles a pte_mapped trace event.
# Returns: a PlotEvent object on success, or None if there was an error
#   or we don't care about this event for plotting purposes.
def process_pte_mapped(event_match, vma_match, proc_tracker, proc_info):
	tag = 'process_pte_mapped'

	pte_event_line = vma_match.group('rest').strip()
	pte_match = pte_mapped_re.match(pte_event_line)
	if not pte_match:
		print_unexpected(True, tag, ("pte_match failed on {}").format(
			pte_event_line))
	
	kernel_timestamp = float(event_match.group('timestamp'))
	vma_begin_addr = int(pte_match.group('begin_addr'), 16)
	vma_end_addr = int(pte_match.group('end_addr'), 16)
	filename = pte_match.group('filename').strip()
	faultaddr = int(pte_match.group('faultaddr'), 16)
	if int(pte_match.group('is_major')) == 0:
		is_major = False
	else:
		is_major = True
	old_pfn   = int(pte_match.group('old_pfn'))
	old_flags = int(pte_match.group('old_flags'), 16)
	new_pfn   = int(pte_match.group('new_pfn'))
	new_flags = int(pte_match.group('new_flags'), 16)
	#print_debug(tag, ("parsed trace line: vma {}-{}, faultaddr={}, "
	#	"is_major={}, old_pfn={}, old_flags={}, new_pfn={}, "
	#	"new_flags={}").format(hex(vma_begin_addr), hex(vma_end_addr),
	#	hex(faultaddr), is_major, old_pfn, hex(old_flags), new_pfn,
	#	hex(new_flags)))
	
	# Eventually, we'll accommodate huge pages here...
	pagesize = PAGE_SIZE_BYTES

	# Keep in mind that when we "link" a pte to a vma in this method,
	# the link represents the vma only at the time of the pte mapping;
	# the vma may soon be unmapped and then remapped, which will
	# actually create a new vm_mapping object in our scripts, so the
	# pte won't point to the "current" vm_mapping.
	#   TODO: during unmap-remap pairs, need to track the set of ptes
	#   linked to the vma so that they can be re-established on the
	#   remapped vma?? Oooof...

	linked_vma = pte_get_linked_vma(proc_info, vma_begin_addr,
					new_pfn)
	if linked_vma:
		pte = PTE(new_pfn, new_flags, pagesize, linked_vma)
		# TODO here: link the vma to the pte?!
	else:
		# todo: do we still want to count the pte event towards
		# the new process? Or just ignore it??
		#   If we're ignoring vma mmap events during fork-execs, then
		#   seems like we might as well ignore pte events too, until
		#   the exec is done and we start getting pte events for the
		#   vmas that the process is actually using.
		#pte = PTE(new_pfn, new_flags, pagesize, None)
		pte = None
		if filename and len(filename) > 1:
			# We expect this to happen for processes that we haven't
			# seen full info for, at least...
			print_unexpected(False, tag, ("got filename {} from pte {} "
				"{}, but no linked vma found").format(filename, new_pfn,
				new_flags))
	
	if pte:
		page_event = PageEvent(pte, kernel_timestamp, unmap=False)
		plot_event = PlotEvent(page_event=page_event)
	else:
		plot_event = None

	return plot_event

# Handles a pte_* trace event.
# Returns: a PlotEvent object on success, or None if there was an error
#   or we don't care about this event for plotting purposes.
def process_pte_trace_event(event_match, vma_match, proc_tracker, tgid,
		linenum, usermodule, userfn):
	tag = 'process_pte_trace_event'

	pte_event_type = event_match.group('trace_event').strip()
	pte_event_msg = event_match.group('event_msg').strip()
	proc_info = proc_tracker.get_process_info(tgid)
	plot_event = None

	# Switch on pte_event_type, which corresponds to a particular trace
	# event declared in include/trace/events/pte.h.
	if pte_event_type == 'pte_mapped':
		plot_event = process_pte_mapped(event_match, vma_match,
				proc_tracker, proc_info)
	elif pte_event_type == 'pte_update':
		pass
	elif pte_event_type == 'pte_at':
		pass
	elif pte_event_type == 'pmd_at':
		# saw this in firefox trace from stjohns over ssh-X...
		pass
	elif pte_event_type == 'pte_cow':
		pass
	elif pte_event_type == 'pte_fault':
		pass
	elif pte_event_type == 'pte_printk':
		# Most of the time we don't want to ignore pte_printk messages;
		# they alert us to conditions in the kernel that need to be
		# traced more carefully.
		#   do_pmd_numa_page: seen for firefox trace from stjohns-X
		#   do_numa_page: same
		ignorefns = []
		#ignorefns = ['buffer_migrate_page', 'migrate_page',
		#		'move_to_new_page', 'do_pmd_numa_page', 'do_numa_page',]
		ignore = False
		for fn in ignorefns:
			if fn in pte_event_msg:
				ignore = True
				break
		if not ignore:
			print_unexpected(True, tag, ("pte_printk: {}").format(
				pte_event_msg))
		else:
			print_debug(tag, ("ignoring this pte_printk: {}").format(
				pte_event_msg))
	else:
		print_unexpected(True, tag, ("unexpected pte_event_type "
			"{}").format(pte_event_type))

	# bookmark TODO
	#proc_info.update_pte_stats(pte_event_type)

	return plot_event

def handle_userstacks_if_needed(process_userstacks, event_match,
		vma_match, ip_to_fn, trace_f, linenum, mmap_pid, tgid,
		proc_tracker):
	tag = 'handle_userstacks_if_needed'

	# If options/userstacktrace was enabled for kernel tracing,
	# then *after* every kernel trace event there will also be
	# a <user stack trace> event, followed by zero or more
	# user-space stack entries. Process these lines now: this
	# method will attempt to determine the user-space "module"
	# that is responsible for this kernel trace event.
	#
	# This method will *NOT* advance the line pointer in trace_f!
	# It *will* look forward "through" any possible interleavings
	# from separate CPUs, until the next kernel event for this
	# cpu is hit, before it gives up the stack-unwind. In this
	# outer method then, we will have to iterate over these lines
	# again and ignore them until we hit another kernel event.

	if not process_userstacks:
		return (MODULE_DISABLED, FN_DISABLED)
	if not vma_match:
		# Right now we don't expect to care about userstacktrace module
		# or function if not a vma-related event.
		return (None, None)
	
	task = event_match.group('task')
	cpu = int(event_match.group('cpu'))
	trace_event = event_match.group('trace_event')
	fork_event = is_fork_event(vma_match)
	exec_event = is_definitely_exec_event(trace_event,
		vma_match, just_first_exec=True)

	return process_userstack_events(ip_to_fn, trace_f, linenum,
			task, mmap_pid, tgid, cpu, proc_tracker, fork_event,
			exec_event)

# Handles an mmap_* trace event.
# Returns a tuple: (is_plot_event, modifiedvma).
def process_mmap_trace_event(event_match, vma_match, proc_tracker,
		tgid, linenum, usermodule, userfn):
	tag = 'process_mmap_trace_event'

	if not event_match:
		print_error_exit(tag, ("event_match None").format())

	#event_pid = int(event_match.group('pid'))
	#flags = event_match.group('flags')
	task = event_match.group('task')
	cpu = int(event_match.group('cpu'))
	kernel_timestamp = float(event_match.group('timestamp'))
	trace_event = event_match.group('trace_event')
	event_msg = event_match.group('event_msg')
	proc_info = proc_tracker.get_process_info(tgid)
	proc_context = proc_info.get_context()

	# These will be set based on the big event switch on
	# trace_event below:
	action = None
	addr_must_match = None
	vma_op = None
	is_plot_event = False
	modifiedvma = None

	# Switch on trace events that we care about:
	if trace_event == 'mmap_printk':
		print_warning(tag, ("trace printk: {0}").format(event_msg))
	elif proc_context['sim_enabled']:
		# Note: vma_match may still be None at this point, for
		# mmap_disable_sim events.

		# If we know that this process was started via a fork-exec,
		# then we want to skip certain trace events which cause
		# the analysis and vma counting to get a little bit messy:
		# the dup_mmap events that duplicate the mmap during the
		# fork, and the exit_mmap events that remove the old
		# duplicated mmap during the exec. Fortunately, in
		# map_unmap_vma() we already keep track of when we're
		# in the set of exit_mmap events for an exec (as opposed
		# to the exit_mmap events that naturally come when a
		# process is exiting).
		#   I examined this code path for exec_follows_fork set
		#   to both False and True, and when True, it looks like
		#   it correctly skips the dup_mmap and exit_mmap events
		#   during the fork-exec, but doesn't skip the
		#   __bprm_mm_init and other exec-related events. Woooo!
		# This code should only ever impact dup_mmap and exit_mmap
		# events, so it seems fairly safe - it shouldn't interfere
		# with sim_disable, userstack processing, or other events...
		if (proc_info.exec_follows_fork and
			(is_fork_event(vma_match) or
			 (is_exit_event(vma_match) and proc_info.use_bprm))):
			#print_debug(tag, ("line {} is an mmap_vma_* trace "
			#	"event that's duplicating or removing the mmap "
			#	"for {} which does a fork-exec - we should "
			#	"ignore this event for analysis purposes!").format(
			#	linenum, proc_info.name()))
			is_fork_exec_event = True
			#print_debug(tag, ("line {}: {}: is_fork_exec_event="
			#	"{}").format(linenum, proc_info.name(),
			#	is_fork_exec_event))
		else:
			is_fork_exec_event = False

		# If we want to skip this fork/exec event, I think it's
		# safe to just continue to the next line. We've done
		# everything that we want/need to do with this fork
		# event (like setting the process hierarchy, etc.) above,
		# and below all we do is call map_unmap_vma(), which
		# we now want to skip. We will not call handle_plot_event
		# for time-series events either.
		#
		# I examined the output of the vma-counts plot for dedup
		# and for a kernelbuild with these events ignored and not
		# ignored, and I think the handling of them is correct.
		# For dedup, the plot has the same shape except it's
		# missing the big spike up to 250 vmas at the very
		# beginning; because of this, the y-scale is smaller, so
		# the jaggedness of the plot looks more pronounced, but
		# I think it's correct. For the kernelbuild, the plot
		# looks pretty much identical; a few of the peaks are
		# smaller, but the biggest peak happens after the libs
		# have been loaded for an "svn" child process (not
		# because of a fork), so the overall max vma count does
		# not change when these events are ignored. Great.
		if is_fork_exec_event and ignore_fork_exec_events:
			#print_debug(tag, ("skipping over fork/exec event on "
			#	"line {}, returning (False, None) to continue "
			#	"to next line").format(linenum))
			return (False, None)

		# Ok, now do the actual event / vma / mmap handling:
		call_map_unmap_vma = True
		if (trace_event == "mmap_vma_alloc" or
				trace_event == "mmap_vma_alloc_dup_mmap"):
			# mmap_vma_alloc_dup_mmap is the same as mmap_vma_alloc,
			# just specialized for the dup_mmap kernel function.
			action = "map"
			vma_op = 'alloc'
			check_context_for_event_pairs(proc_context)
			  # Added 12/20 for sanity checking: ensure that
			  # unmap-remaps are always paired, with no allocs
			  # or frees in-between.
		elif trace_event == "mmap_vma_free":
			action = "unmap"
			vma_op = 'free'
			check_context_for_event_pairs(proc_context)
		elif trace_event == "mmap_vma_resize_unmap":
			action = "unmap"
			vma_op = 'resize'
			begin_event_pair(vma_op, proc_info, vma_match)
		elif trace_event == "mmap_vma_resize_remap":
			action = "map"
			vma_op = 'resize'
			addr_must_match = False
			end_event_pair(vma_op, proc_info, vma_match,
				addr_must_match)
		elif trace_event == "mmap_vma_reloc_unmap":
			action = "unmap"
			vma_op = 'relocation'
			begin_event_pair(vma_op, proc_info, vma_match)
		elif trace_event == "mmap_vma_reloc_remap":
			action = "map"
			vma_op = 'relocation'
			addr_must_match = False
			end_event_pair(vma_op, proc_info, vma_match,
				addr_must_match)
		elif trace_event == "mmap_vma_access_unmap":
			action = "unmap"
			vma_op = 'access_change'
			begin_event_pair(vma_op, proc_info, vma_match)
		elif trace_event == "mmap_vma_access_remap":
			action = "map"
			vma_op = 'access_change'
			addr_must_match = True
			end_event_pair(vma_op, proc_info, vma_match,
				addr_must_match)
		elif trace_event == "mmap_vma_flags_unmap":
			action = "unmap"
			vma_op = 'flag_change'
			begin_event_pair(vma_op, proc_info, vma_match)
		elif trace_event == "mmap_vma_flags_remap":
			action = "map"
			vma_op = 'flag_change'
			addr_must_match = True
			end_event_pair(vma_op, proc_info, vma_match,
				addr_must_match)
		elif trace_event == "mmap_enable_sim":
			print_error_exit(tag, ("{0}: sim_enabled is already "
				"True!").format(trace_event))
		elif trace_event == "mmap_disable_sim":
			proc_context['sim_enabled'] = False
			#print_debug(tag, ("disabling simulation!: {0}").format(
			#	event_msg))
			call_map_unmap_vma = False
		elif trace_event == "mmap_reset_sim":
			print_error_exit(tag, ("dead code: mmap_reset_sim "
				"is no longer a good idea, disabled it!").format())
			#reset_sim_for_proc(proc_info)
			#call_map_unmap_vma = False
		else:
			print_unexpected(True, tag, ("skipping trace_event that "
				"we don't handle: {0}").format(trace_event))
			# mmap_printk events will hit this - for now, treat this as
			# an error, I want the script to fail so I can inspect these!
			print_unexpected(True, tag, ("unhandled trace_event {}; "
				"event_msg={}").format(trace_event, event_msg))
			call_map_unmap_vma = False

		if call_map_unmap_vma:   # usually true
			modifiedvma = map_unmap_vma(action, vma_match,
				proc_info, vma_op, kernel_timestamp, usermodule,
				userfn, proc_tracker)
			is_plot_event = True

	else:   # proc_context['sim_enabled'] == FALSE
		if trace_event == "mmap_enable_sim":
			proc_context['sim_enabled'] = True
			#print_debug(tag, ("enabling simulation: {0}").format(
			#	event_msg))
		elif trace_event == "mmap_disable_sim":
			print_error_exit(tag, ("{0}: sim_enabled is already "
				"False!").format(trace_event))
		else:
			pass   # ignore all other events while sim disabled
		is_plot_event = False
		modifiedvma = None

	return (is_plot_event, modifiedvma)

# When a kernel trace event with some vma information is received (most
# mmap_* and pte_* trace events), performs the following steps:
#   Sets the process name if not already set.
#   Handles fork + exec stuff.
# Returns: nothing.
def do_common_vma_processing(vma_match, trace_event, event_pid,
		task, proc_info, proc_tracker, tgid, group_multiproc,
		target_pids, trace_f, linenum):
	tag = 'do_common_vma_processing'

	# Set the process' name. The process name comes from the existing
	# trace infrastructure, not from our trace events; however, we may
	# emit trace events attributed to a particular process in the
	# "context" of another process (e.g. dup_mmap events: when a fork
	# occurs, we emit trace events in the context of the parent, but
	# attributed to the child process). So, only set the process'
	# name when we know that the trace-infrastructure pid matches
	# the pid (not tgid!) from our trace events.
	# For a process that is forked and then performs an exec, it
	# looks like the task name is available (from task =
	# event_match.group('task')) as soon as the exec is performed,
	# in the __bprm_mm_init kernel function.
	# For a child process that is forked but never performs an
	# exec, the child process may set a different task name at
	# some point... but I haven't checked when yet, we may
	# miss it by checking if is_progname_set() already here.
	if ((not proc_info.is_progname_set()) and
			vma_match and event_pid == int(vma_match.group('pid'))):
		proc_info.set_progname(task)
		print_debug(tag, ("set process name {}").format(
			proc_info.name()))

	# We want to know whether or not we have seen the very
	# first trace events for a process, which come during the
	# call to dup_mmap() that happens during a fork.
	# Note that this only works after we have adjusted the
	# pid / tgid above.
	# BUG: this will fail if the trace happens to be started
	# in the middle of a dup_mmap() - we'll set saw_fork to
	# true here, but we won't end up tracking the vmas at the
	# beginning of the mmap that were duplicated before the
	# trace started. Oh well - this seems pretty unlikely to
	# happen, and if it does, can just re-capture the trace.
	# 
	# ALSO: during kernel builds, apparently it is possible to
	# start a new process that gets a different pid AND tgid
	# without duplicating the parent process' memory map!
	# (by calling clone() with CLONE_VM, but neither CLONE_THREAD
	# nor CLONE_PARENT?) Call this an "empty clone"; I added a
	# trace event to the kernel to confirm that this particular
	# combination of CLONE_ flags does indeed happen sometimes.
	#   Ohhhhhhhhh: I think make is being sneaky and instead of
	#   calling a traditional fork-then-exec, it's calling clone
	#   with CLONE_VM set followed immediately by exec, to avoid
	#   the work of duplicating the mmap!
	# This broke my assumption that for all new tgids we would
	# observe their dup_mmap events. Will we see an *exec* event
	# (__bprm_mm_init) for this new tgid?
	#   It doesn't seem like we HAVE to, but during the kernel
	#   build it looks like we do - in the trace that I examined
	#   closely anyway, the very first event that's emitted for
	#   the new tgid is a __bprm_mm_init.
	# SO, if we receive a __bprm_mm_init event for a process whose
	# ptgid is not yet set, call handle_multiproc as well, to set
	# the ptgid appropriately. Then, in places where we currently
	# check for saw_fork==True to determine whether or not to
	# analyze something, we have to change this to check saw_exec
	# as well.
	# Uh oh: in a cassandra trace, I found that java-27101 is forking
	# off a child process id-27417 (with tgid also 27417) that runs
	# in java-27101's address space, as described above, BUT the first
	# event that we receive for id-27417 is NOT a __bprm_mm_init event!
	#   id-27417 [014] ....     7980454658445: mmap_vma_resize_unmap:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [vma_merge cases 2,5,7 -> vma_adjust]: ...
	#   id-27417 [014] ....     7980454663986: mmap_vma_resize_remap:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [vma_merge cases 2,5,7 -> vma_adjust]: ...
	#   id-27417 [014] ....     7980454667720: mmap_vma_resize_unmap:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [vma_merge cases 2,5,7 -> vma_adjust]: ...
	#   id-27417 [014] ....     7980454670892: mmap_vma_resize_remap:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [vma_merge cases 2,5,7 -> vma_adjust]: ...
	#   id-27417 [014] ....     7980454674800: mmap_vma_access_unmap:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [mprotect_fixup]: ...
	#   id-27417 [014] ....     7980454684441: mmap_vma_access_remap:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [mprotect_fixup]: ...
	#   id-27417 [016] ....     7980454920806: mmap_vma_alloc:
	#     pid=27417 tgid=27417 ptgid=27101
	#     [__bprm_mm_init]:...
	# What the heck do I need to do to handle this correctly? Well,
	# for the first three unmap-remap events, I need to somehow know
	# that they should be attributed to the ptgid 27101; this could
	# perhaps be done by looking ahead in the trace, but who knows
	# how far ahead we have to look, so really I need to add a new
	# kernel trace event for this.
	#   TODO: actually do this in the kernel code, and then add a
	#   new field to the process_info object (somethind like
	#   "shared_mmap"?) that points to the parent's mmap for use
	#   in map_unmap_vma... and here we need to make sure that we
	#   consider this child thread/process "relevant" and don't
	#   skip it's events :(
	# THEN, when I finally hit the
	# __bprm_mm_init for the child process/thread, I need to use a
	# new mmap - I'm pretty sure that the way that the kernel code
	# works here is that __bprm_mm_init is part of the exec which
	# is creating a new empty mmap, and then the refcount on the
	# old mmap (java-27101) is decremented (see exec_mmap() in the
	# kernel code), and then id-27417 just proceeds with a new mmap.
	# I think that this part should just work with my trace events
	# and analysis scripts right now; the mmput(old_mm) won't actually
	# release the mmap because it's still in use by java-27171, so
	# no exit_mmap events will be emitted at this point for either
	# process, and I'll have just created id-27417's process_info
	# object so it will already have an empty vmatable.
	fork_event = is_fork_event(vma_match)
	first_exec_event = is_definitely_exec_event(trace_event,
			vma_match, just_first_exec=True)
	  # first_exec_event will be True only for __bprm_mm_init
	  # kernel events.

	if fork_event:
		if not proc_info.saw_fork:   # first fork for this process
			# Call lookahead_fork_exec to see if this process,
			# which is currently being forked in the trace, will
			# perform an exec. Later in the analysis, we can
			# check the .exec_follows_fork field of the proc_info
			# and if it is true, we can skip analysis of the
			# process' fork events, since it may not really make
			# sense to account for them (this is just an artifact
			# of the dumb old fork-exec design), and these events
			# disrupt various vma counts that we perform.
			# Note that exec_follows_fork is *reset* for the
			# proc_info in map_unmap_vma. (it's a bit unfortunate
			# that this field is set/reset in two different
			# locations, but that method knows exactly when
			# the fork-exec process is complete).
			will_exec = lookahead_fork_exec(trace_f, linenum,
					vma_match)
			proc_info.set_exec_follows_fork(will_exec)
			print_debug(tag, ("{}: set exec_follows_fork="
				"{}").format(proc_info.name(),
				proc_info.exec_follows_fork))
		proc_info.set_saw_fork(True)
	if first_exec_event:
		proc_info.set_saw_exec(True)
	if fork_event or first_exec_event:
		# Originally, handle_multiproc was only called after a
		# fork_event. However, during Linux kernel builds, we
		# might now see an exec without seeing a fork first, so
		# call handle_multiproc in this case as well - this
		# method should still be able to handle the setting of
		# the ptgid.
		#   This was the handle_multiproc result for one of the
		#   sub-make processes:
		#     DEBUG: handle_multiproc: whew, done: for child
		#     unknown-3762, is_rootproc=False and tgid_for_stats=3757
		#   This is good: as expected, the tgid_for_stats was
		#   set to the top-level make process.
		if first_exec_event and not proc_info.saw_fork:
			print_debug(tag, ("new code path hit: "
				"first_exec_event seen, but not already "
				"saw_fork! is_ptgid_set={}").format(
				proc_info.is_ptgid_set()))

		# At this point, tgid is set to the pid of the child
		# process. Ideally, we would be able to just use the
		# event_pid here as the parent tgid, BUT it turns out
		# that child *threads* may call dup_mmap, causing the
		# event_pid to be a thread pid and not a parent process
		# tgid. So, we had to explicitly add the *parent* tgid,
		# "ptgid", to the kernel messages, so we can know exactly
		# who the parent process is.
		# If this is the first message for a fork of this child,
		# then we call handle_multiproc to properly store the
		# ptgid field and possibly use the process hierarchy
		# to "group" child processes together with their
		# parent processes.
		if not proc_info.is_ptgid_set():
			handle_multiproc(vma_match, proc_tracker, tgid,
				proc_info, group_multiproc, target_pids)

	return

# Classifies a kernel trace event match into a small set of categories,
# determined by the trace event names defined by the kernel.
# Returns: a trace_event_type string.
def determine_trace_event_type(event_match):
	tag = 'determine_trace_event_type'

	trace_event = event_match.group('trace_event')

	if re.compile(r'^pte_').match(trace_event):
		trace_event_type = 'pte'
	elif re.compile(r'^pmd_').match(trace_event):
		trace_event_type = 'pmd'
	elif re.compile(r'^mmap_').match(trace_event):
		trace_event_type = 'mmap'
	elif re.compile(r'^sched_').match(trace_event):
		trace_event_type = 'sched'
	elif (re.compile(r'^sys_enter_').match(trace_event) or
	      re.compile(r'^sys_exit_').match(trace_event)):
		trace_event_type = 'syscall'
	elif trace_event == 'tracing_mark_write':
		trace_event_type = 'checkpoint'
	else:
		trace_event_type = 'other'
	
	return trace_event_type

def process_trace_file(trace_f, proc_tracker, outputdir, group_multiproc,
		process_userstacks, lookup_fns, target_pids, plotlist,
		current_appname, skip_page_events):
	tag = "process_trace_file"

	cpu_tracker = cpus_tracker()
	if lookup_fns:
		# If we're going to perform ip-to-function lookups, we need the
		# converter to live for the entire analysis, so create it here.
		# Remember to call close() on it before we exit, or else its
		# addr2line subprocesses will hang around longer than necessary.
		ip_to_fn = ip_to_fn_converter()
	else:
		ip_to_fn = None

	skip_irrelevant_processes = True
	if skip_irrelevant_processes:
		print_debug(tag, ("skip_irrelevent_processes is True, so "
			"any processes not in target_pids {} and not descendants "
			"of those pids will be ignored").format(target_pids))
	if skip_page_events:
		print_debug(tag, ("skip_page_events True, will skip all "
			"pte_* trace events").format())

	linenum = 0
	line = None
	while True:
		linenum += 1
		line = trace_f.readline()
		if not line:
			break
		print_debug(current_appname, "line #:\t{0}".format(linenum))
		#if linenum == 1 + 160587:
		#	print_error_exit(tag, ("stopping after line {}").format(linenum-1))

		cont_outer_loop    = False
		event_match        = None
		stack_begin_match  = None
		stack_entry_match  = None
		while True:
			# If we don't check this first, a comment line may actually
			# match trace_event_re, because trace tasks may actually
			# include ' ' and '#' in their name! ooof.
			if line[0] == '#':
				cont_outer_loop = True
				#print_debug(tag, ("skipping comment line").format())
				break

			# This matches most of my mmap and pte kernel trace events,
			# but not all; e.g. trace_mmap_printk, trace_pte_printk,
			# trace_pte_at do not have the same format.
			event_match = trace_event_re.match(line)
			if event_match:
				break

			# Check for expected lines that we want to skip in the outer
			# loop - inner methods (namely process_userstack_events())
			# should have already processed these.
			cont_outer_loop = True
			if len(line) == 1:
				#print_debug(tag, ("skipping blank line").format())
				break
			stack_begin_match = userstacktrace_begin_re.match(line)
			if stack_begin_match:
				#print_debug(tag, ("skipping userstack-begin line {0} "
				#	"in outer loop - inner method should have already "
				#	"processed it!").format(linenum))
				break
			stack_entry_match = userstacktrace_entry_re.match(line)
			if stack_entry_match:
				#print_debug(tag, ("skipping userstack entry line {0} "
				#	"in outer loop - inner method should have already "
				#	"processed it!").format(linenum))
				break
			stack_reason_match = userstacktrace_reason_re.match(line)
			if stack_reason_match:
				break
			# this may happen e.g. if we enable strace events:
			print_unexpected(True, tag, ("skipping line that didn't "
				"match any of the expected regexes: [{0}]").format(
				line[:-1]))
			break  # this is kind of a do-while(False) loop
		if cont_outer_loop:
			continue

		# Code for kernel events:
		if event_match:
			trace_event_type = determine_trace_event_type(event_match)
			if (skip_page_events and
				(trace_event_type == 'pte' or trace_event_type == 'pmd')):
				#print_debug(tag, ("skipping page event and continuing "
				#	"loop").format())
				continue

			task = event_match.group('task')
			event_pid = int(event_match.group('pid'))
			#cpu = int(event_match.group('cpu'))
			#flags = event_match.group('flags')
			#kernel_timestamp = float(event_match.group('timestamp'))
			trace_event = event_match.group('trace_event')
			event_msg = event_match.group('event_msg')

			# Possibly use the tgid from this event to override the pid
			# we got from the initial kernel trace event infrastructure:
			# that pid may actually be a *thread* pid, not a top-level
			# process tgid!
			# We do this here with vma_pids_re, rather than below with
			# vma_event_re, because some events (namely mmap_disable_sim
			# and mmap_enable_sim, which are emitted during process
			# exec) do not match the vma format, but do need pid / tgid
			# overriding.
			pids_match = vma_pids_re.match(event_msg)
			if pids_match:
				mmap_pid = int(pids_match.group('pid'))
				tgid = int(pids_match.group('tgid'))
			else:
				# Make sure that the event is a "global" event that
				# doesn't need to match a specific process; most events
				# should correspond to a specific tgid!
				mmap_pid = None
				tgid = event_pid

			# Set up process info struct:
			proc_info = proc_tracker.get_process_info(tgid)
			if proc_info:   # already seen this tgid before:
				# Don't check proc_info.get_progname() against task,
				# because the trace messages may output user-level
				# threads that belong to the same tgid but have
				# different task names.
				if proc_info.get_pid() != tgid:
					print_error_exit(tag, ("got process_info for "
						"pid {0}, but its progname {1} or pid {2} doesn't "
						"match trace file's task {3} or pid {4}!?!").format(
						tgid, proc_info.get_progname(),
						proc_info.get_pid(), task, tgid))
			else:   # first time this tgid has been encountered:
				proc_info = new_proc_info(tgid, proc_tracker)
				  # just store the tgid as the process' pid - for now
				  # we want to "coalesce" all threads from the same
				  # tgid into one proc_info.

			# There are now some steps that we want to perform no matter
			# whether the trace event type is "mmap" (for virtual memory
			# events) or "pte" (for physical page events). It is beneficial
			# for these events to have the same format at the beginning
			# of their output lines, so that the same regexes will work
			# for both.
			#   For now, these events are all associated with some
			#   particular vma, so look for that in the trace line and
			#   use it for common steps.
			vma_match = vma_event_re.match(event_msg)
			if vma_match:
				# TODO: just pass event_match to this method, instead
				# of task and event_pid and whatnot...
				do_common_vma_processing(vma_match, trace_event,
					event_pid, task, proc_info, proc_tracker,
					tgid, group_multiproc, target_pids, trace_f,
					linenum)

			# Ok, do_common_vma_processing handled process name and
			# fork/exec stuff. Now that we have all of that information
			# stored in the proc_info, make sure that we care about
			# events for this process; if we don't, then continue
			# loop to get next trace line.
			# After adding this performance optimization, I verified
			# that a long chrome trace resulted in exactly the same
			# plots before and after. Also, the runtime with irrelevent
			# events skipped was 20% shorter, wooo.
			(relevant, tgid_for_stats) = is_relevant(
					proc_tracker, group_multiproc,
					target_pids, tgid, trace_event_type, task)
			if skip_irrelevant_processes and not relevant:
				#print_debug(tag, ("skipping event for irrelevant "
				#	"process: {}").format(proc_info.name()))
				continue
			if tgid_for_stats == 0:
				# this could happen if skip_irrelevant_processes is
				# False and we get events for the <idle> process...
				print_unexpected(True, tag, ("tgid_for_stats={} - "
					"double-check that this is the idle process ({}), "
					"and beware of errors from methods below if we "
					"use 0 for tgid_for_stats").format(
					tgid_for_stats, proc_info.name()))

			# Move userstack handling to here, outside of
			# process_*_trace_event, to avoid having to pass a
			# bazillion special arguments down to them. If
			# vma_match is None, this method will return immediately.
			(usermodule, userfn) = handle_userstacks_if_needed(
				process_userstacks, event_match, vma_match,
				ip_to_fn, trace_f, linenum, mmap_pid, tgid,
				proc_tracker)

			# Now, call separate methods to handle original trace events
			# of the mmap_* variety, newer trace events of the pte_*
			# variety, and other trace event types that the kernel already
			# defines. Each of these handler methods will tell us if
			# we need to call the plot method below.
			# The pte_* events may or may not have a successful vma_match
			# from above.
			modifiedvma = None
			is_plot_event = False
			plot_event = None
			if trace_event_type == 'mmap':
				(is_plot_event, modifiedvma) = process_mmap_trace_event(
					event_match, vma_match, proc_tracker, tgid,
					linenum, usermodule, userfn)
				if is_plot_event and modifiedvma:
					plot_event = PlotEvent(vma=modifiedvma)
			elif (trace_event_type == 'pte' or 
					trace_event_type == 'pmd'):
				plot_event = process_pte_trace_event(
					event_match, vma_match, proc_tracker, tgid,
					linenum, usermodule, userfn)
			elif trace_event_type == 'sched':
				(is_plot_event, modifiedvma) = process_sched_trace_event(
					trace_event, event_match, cpu_tracker, proc_tracker)
				if is_plot_event or modifiedvma:
					plot_event = PlotEvent(vma=modifiedvma)
			elif trace_event_type == 'syscall':
				print_error_exit(tag, ("not implemented yet: "
					"trace_event_type {}").format(trace_event_type))
			elif trace_event_type == 'checkpoint':
				# This event occurs when a value is echoed to
				# /sys/kernel/debug/tracing/trace_marker while tracing
				# is activated. This value is kept in the event_msg.
				# For now this is used to indicate "checkpoints" during
				# the application's execution.
				plot_event = handle_trace_marker(event_match, proc_tracker,
						outputdir, group_multiproc, target_pids,
						current_appname)
				#print_debug(tag, ("handle_trace_marker returned a "
				#	"plot_event with cp_event={}").format(
				#	plot_event.cp_event))
			else:
				print_unexpected(True, tag, ("got trace_event {} "
					"that doesn't match any expected "
					"trace_event_types ({})").format(trace_event,
					trace_event_type))

			# If the kernel event should be considered for plots, call
			# handle_plot_event().
			if plot_event:
				if proc_info.get_pid() != tgid:
					print_error_exit(tag, ("proc_info pid doesn't "
						"match tgid before calling handle_plot_event! "
						"{} {}").format(proc_info.get_pid(), tgid))
				handle_plot_event(plot_event, plotlist, tgid, target_pids,
					proc_tracker, group_multiproc, current_appname,
					tgid_for_stats, skip_irrelevant_processes)

		else:
			print_error_exit(tag, ("hit dead code path for Pin events"))

		# loop to next line

	end_final_sched_quantum(cpu_tracker, proc_tracker)
	if ip_to_fn:
		ip_to_fn.close()

	return

# if add_fn is None, then just add using '+'
def add_maps(dest, src, add_fn):
	tag = "add_maps"
	
	print_warning(tag, "not implemented yet!")
	return

def query_module_segment_ops(outputdir, proc_groups, whichtable):
	tag = "query_module_segment_ops"

	module_fname = "{0}/segment_ops_modules.out".format(outputdir)
	module_f = open(module_fname, 'w')

	#for proc_info in proc_tracker.get_all_process_infos():
	for proc_group in proc_groups:
		root_proc = proc_group[0]
		def module_segment_ops_query_fn(vma):
			op = vma.vma_op
			# Do we care if vma is mapped or unmapped? No.
			#if (op == 'alloc' or op == 'resize' or op == 'access_change'):
			if op in SEGMENT_OPS:
				return [vma.creator_module]
			return None   # don't care about
		(module_map, totalvmas) = query_vmas_grouped(proc_group,
			module_segment_ops_query_fn, whichtable)

		sorted_modules = sorted(module_map.items(),
			key=lambda kv: len(kv[1]))
			# Can't directly use tuple in lambda:
			#   http://www.python.org/dev/peps/pep-3113/
		if len(sorted_modules) > 0:
#			module_f.write(("\n{0}-{1} Modules:\n").format(
#				proc_info.get_progname(), proc_info.get_pid()))
			module_f.write(("\n{} Modules:\n").format(root_proc.name()))
		total = 0
		for (module, vmalist) in sorted_modules:
			total += len(vmalist)
		if total > 0:
			module_f.write(("Total\t{0}\tvma ops\n").format(total))
		for (module, vmalist) in sorted_modules:
			module_f.write(("{0}\t{1}\tvma ops\t({2:.2f}%)\n").format(
				module, len(vmalist),
				100 * len(vmalist) / total))

	module_f.close()
	return	

def query_fn_segment_ops(outputdir, proc_groups, whichtable):
	tag = "query_fn_segment_ops"

	fn_fname = "{0}/segment_ops_fns.out".format(outputdir)
	fn_f = open(fn_fname, 'w')

	for proc_group in proc_groups:
		root_proc = proc_group[0]
		def fn_segment_ops_query_fn(vma):
			op = vma.vma_op
			# Do we care if vma is mapped or unmapped? No.
			#if (op == 'alloc' or op == 'resize' or op == 'access_change'):
			if op in SEGMENT_OPS:
				return [vma.creator_fn]
			return None   # don't care about
		(fn_map, totalvmas) = query_vmas_grouped(proc_group,
			fn_segment_ops_query_fn, whichtable)

		sorted_fns = sorted(fn_map.items(),
			key=lambda kv: len(kv[1]))
		if len(sorted_fns) > 0:
			fn_f.write(("\n{} Functions:\n").format(root_proc.name()))
		total = 0
		for (fn, vmalist) in sorted_fns:
			total += len(vmalist)
		if total > 0:
			fn_f.write(("Total\t{0}\tvma ops\n").format(total))
		for (fn, vmalist) in sorted_fns:
			fn_f.write(("{0}\t{1}\tvma ops\t({2:.2f}%)\n").format(
				fn, len(vmalist),
				100 * len(vmalist) / total))

	fn_f.close()
	return

def query_module_segsizes(outputdir, proc_groups, whichtable):
	tag = "query_module_segsizes"

	# segset_to_plot() uses a segset: a dictionary whose keys are segment
	# sizes and whose values are tuples of the form (num-segments,
	# max-num-segments). So, first run a query that sorts the vmas by
	# module, filtering out the vmas that don't match the "segments ops"
	# that we care about. Then, for each module, run another query/hash
	# to sort its vmas by size, then convert these lists of vmas into
	# just counts which the segset plot method will understand. Whew.
	for proc_group in proc_groups:
		root_proc = proc_group[0]
#		if not proc_info.have_full_info():
#			print_debug(tag, ("skipping expensive segset plot query "
#				"for {} because we didn't see its fork").format(
#				proc_info.name()))
#			continue
		def module_query_fn(vma):
			op = vma.vma_op
			# Do we care if vma is mapped or unmapped? No; we just care
			# about all vmas that were ever created by an allocation or
			# a resize operation.
			if op in SEGMENT_OPS:
				return [vma.creator_module]
			return None   # don't care about
#		(module_map, totalvmas) = proc_info.query_vmas(
#			module_query_fn, whichtable)
		(module_map, totalvmas) = query_vmas_grouped(proc_group,
			module_query_fn, whichtable)
		for (module, vmalist) in module_map.items():
			# Ok, now we have a list of vmas that correspond to segment
			# ops for each module. We want to turn this list of vmas
			# into a segset that can be plotted:
			def segsize_hash_fn(vma):
				return [vma.seg_size]
			(module_segset, totalvmas2) = construct_dict_from_list(
				vmalist, segsize_hash_fn)
			for (segsize, vmas) in module_segset.items():
				# segset plot requires a tuple of (count, maxcount):
				module_segset[segsize] = (len(vmas), len(vmas))
			modulename = module.rpartition('/')[2]
#			module_plotname = "{}/{}-{}-segplot-{}".format(
#				outputdir, proc_info.get_progname(),
#				proc_info.get_pid(), modulename)
#			segset_to_plot(module_segset, module_plotname,
#				proc_info.get_progname(), None)
			module_plotname = "{}/{}-segplot-{}".format(
				outputdir, root_proc.name(), modulename)
			segset_to_plot(module_segset, module_plotname,
				root_proc.get_progname(), None)

	return

# Examines the operations that change the access permissions of a
# vma, and divides them into "explicit" operations (e.g. direct calls
# to mprotect) and "implicit" operations (e.g. mmap calls that overlap
# existing regions with different permissions).
def query_mprotect_sizes(outputdir, proc_groups, whichtable):
	tag = "query_mprotect_sizes"

	# segset_to_plot() uses a segset: a dictionary whose keys are segment
	# sizes and whose values are tuples of the form (num-segments,
	# max-num-segments). So, run a query that sorts the vmas by size,
	# then convert these lists of vmas into just counts which the segset
	# plot method will understand.
	for proc_group in proc_groups:
		root_proc = proc_group[0]
		# See construct_dict_from_list(): the query functions should
		# return a list of keys.
		def explicit_query_fn(vma):
			#if (vma.vma_op is 'access_change' or
			#	'mprotect_fixup' in vma.kernel_fn):
			#	print_debug("explicit_query_fn",
			#		("op={}, label={}, segsize={}").format(
			#		vma.vma_op, vma.kernel_fn, vma.seg_size))
			if (vma.vma_op is 'access_change' and
				'mprotect_fixup' in vma.kernel_fn):
				return [vma.seg_size]
			return []
		def implicit_query_fn(vma):
			# This query isn't quite right - the kernel trace events
			# that are currently emitted wouldn't actually cause the
			# "implicit" permissions change that I'm thinking of
			# (a new mapping overlapping an existing mapping with
			# different permissions) to emit an access_change event.
			# Currently, mmap_vma_access_[unmap,remap] events are
			# ONLY emitted from mprotect_fixup(), which is ONLY called
			# on the explicit mprotect system call path. In the case
			# of an overlapping mapping, I think that the existing
			# mapping would first be split, and then the new vma arising
			# from the split would have the new permissions applied.
			# If we want this to count as an access_change, we'd have
			# to add more logic to detect this in the kernel and then
			# emit the appropriate event(s)...
			#
			# So right now, this query never returns any results for
			# dedup nor firefox.
			if (vma.vma_op is 'access_change' and
				'mprotect_fixup' not in vma.kernel_fn):
				print_debug("implicit", ("found one!: op={}, "
					"kernel_fn={}").format(vma.vma_op, vma.kernel_fn))
				return [vma.seg_size]
			return []
		(explicit_seglists, explicit_totalvmas) = query_vmas_grouped(
			proc_group, explicit_query_fn, whichtable)
		(implicit_seglists, implicit_totalvmas) = query_vmas_grouped(
			proc_group, implicit_query_fn, whichtable)

		# Construct segset: first item in tuple is explicit count,
		# second item in tuple is implicit count.
		segset = {}
		for (segsize, vmalist) in explicit_seglists.items():
			segset[segsize] = (len(vmalist), 0)
		for (segsize, vmalist) in implicit_seglists.items():
			try:
				explicit_count = (segset[segsize])[0]
				segset[segsize] = (explicit_count, len(vmalist))
			except KeyError:
				segset[segsize] = (0, len(vmalist))
		plotname = "{}/{}-protect-counts".format(
			outputdir, root_proc.name())
		segset_to_plot(segset, plotname,  
			("{} explicit (red) vs. implicit (orange) protection "
				"changes").format(root_proc.get_progname()),
			pid_pdf=None)

		write_segdata = False
		if write_segdata:
			print_error_exit(tag, "this part not implemented yet")
			output_f = open("{}/{}-segdata".format(outputdir,
				root_proc.name()), 'w')
			output_f.write(("Process group: {}\n\n").format(
				proc_group_to_str(proc_group)))
			output_f.write(("Segment size (bytes)\tCount\n").format())
			segsizes = sorted(segset.keys())
			maxsegsize = segsizes[-1]
			segsize = 1
			total = 0
			while segsize <= maxsegsize:
				try:
					count = int(segset[segsize][0])
				except KeyError:
					count = 0
				output_f.write(("{}\t{}\n").format(segsize, count))
				total += count
				segsize *= 2
			output_f.write(("Total\t{}\n").format(total))
			output_f.close()

	return

def query_segsizes(outputdir, proc_groups, whichtable):
	tag = "query_segsizes"

	# segset_to_plot() uses a segset: a dictionary whose keys are segment
	# sizes and whose values are tuples of the form (num-segments,
	# max-num-segments). So, run a query that sorts the vmas by size,
	# then convert these lists of vmas into just counts which the segset
	# plot method will understand.
	for proc_group in proc_groups:
		root_proc = proc_group[0]
		def query_fn(vma):
			return [vma.seg_size]
		(seglists, totalvmas) = query_vmas_grouped(proc_group,
			query_fn, whichtable)
		if totalvmas == 0:
			print_debug(tag, ("skipping segset construction and plot "
				"for {} because it has no vmas (whichtable={})").format(
				root_proc.name(), whichtable))
			continue

		segset = {}
		for (segsize, vmalist) in seglists.items():
			segset[segsize] = (len(vmalist), len(vmalist))
		plotname = "{}/{}-segplot".format(outputdir, root_proc.name())
		segset_to_plot(segset, plotname, root_proc.get_progname(),
			pid_pdf=None)

		write_segdata = True
		if write_segdata:
			output_f = open("{}/{}-segdata".format(outputdir,
				root_proc.name()), 'w')
			output_f.write(("Process group: {}\n\n").format(
				proc_group_to_str(proc_group)))
			output_f.write(("Segment size (bytes)\tCount\n").format())
			segsizes = sorted(segset.keys())
			maxsegsize = segsizes[-1]
			segsize = 1
			total = 0
			while segsize <= maxsegsize:
				try:
					count = int(segset[segsize][0])
				except KeyError:
					count = 0
				output_f.write(("{}\t{}\n").format(segsize, count))
				total += count
				segsize *= 2
			output_f.write(("Total\t{}\n").format(total))
			output_f.close()

	return

def query_vaspace_maps(outputdir, proc_groups, whichtable):
	tag = "query_vaspace_maps"

	output_f = open("{}/maps".format(outputdir), 'w')

	# I don't think it makes much sense to try to "group" processes
	# together for this type of plot, so just "unwrap" each group
	# and plot the proc_info individually:
	for proc_group in proc_groups:
		for proc_info in proc_group:
			print_TODO(tag, ("instead of calling write_proc_map() "
				"directly here, run your own query that uses whichtable "
				"arg...").format())
			proc_info.write_proc_map(output_f)
			output_f.write(("\n").format())
	
	output_f.close()
	return

# Outputs a matrix where the vertical axis divides by operation type
# (e.g. allocate, permissions change) and horizontal access divides by
# permission type.
def query_perms_by_optype(outputdir, proc_groups, whichtable):
	tag = "query_perms_by_optype"
	global VMA_OP_TYPES

	fname = "{}/perms_by_optype".format(outputdir)
	f = open(fname, 'w')
	fcolwidth = max(map(lambda t: len(t), VMA_OP_TYPES)) + 2
	colwidth = 7

	totalstr = 'TOTAL'   # leading space helps with LibreOffice import...
	percentstr = 'Percent'
	header = ["Op type".rjust(fcolwidth)]
	header.append("{0}".format(totalstr.rjust(colwidth)))
	header.append("{0}".format(percentstr.rjust(colwidth)))
	for perms_key in PERMS_KEYS:
		header.append("{0}".format(perms_key.rjust(colwidth)))
	f.write("Counts of vma operations with various permissions, by "
		"operation type\n")
	total_counts = {}

	for proc_group in proc_groups:
		root_proc = proc_group[0]
		def optype_query_fn(vma):
			return [vma.vma_op]
		def access_change_only_query(vma):
			if vma.vma_op == 'access_change':
				return [pretty_bytes(vma.seg_size)]
		(optype_map, proc_totalvmas) = query_vmas_grouped(proc_group,
			#optype_query_fn, whichtable)
			access_change_only_query, whichtable)

		# Skip processes that don't have any vmas in their vmatable
		# or all_vmas tracker:
		if len(optype_map) == 0:
			continue

		f.write("\n")
		f.write("{}\n".format(root_proc.name()))
		f.write("{}\n".format('\t'.join(header)))

		for perms_key in PERMS_KEYS:
			total_counts[perms_key] = 0
		total_counts[totalstr] = 0

		optypelist = []
		for (optype, vmalist) in optype_map.items():
			# First, get counts and totals for this optype:
			def perms_hash_fn(vma):
				return [vma.perms_key]
			(optype_perms_map, meh) = construct_dict_from_list(
				vmalist, perms_hash_fn)
			perms_counts = {totalstr: 0}
			for (perms_key, vmas) in optype_perms_map.items():
				perms_counts[perms_key]  = len(vmas)
				perms_counts[totalstr]  += len(vmas)
				total_counts[perms_key] += len(vmas)
				total_counts[totalstr]  += len(vmas)

			# Now construct output string for this optype, but
			# don't write it yet: save it in a list, which we'll
			# sort by total count and then write out in descending
			# order.
			# We can't calculate the percentages yet, since we don't
			# know the totals across all optypes, so just insert
			# placeholders for now and go back and edit
			# optype_line[2] later.
			#   Note: rpartition no longer needed thanks to
			#   process_userstack_events. Leading space helps when
			#   importing into LibreOffice.
			#   http://docs.python.org/3/library/string.html#format-examples
			optype_line = [(" {0}".format(optype)).rjust(fcolwidth)]
			optype_line.append("{0}".format(
				str(perms_counts[totalstr]).rjust(colwidth)))
			optype_line.append("{0:{w}.2f}%".format(0, w=colwidth-1))
			for perms_key in PERMS_KEYS:   # same order for all optypes
				try:
					count = perms_counts[perms_key]
				except:
					count = 0
				optype_line.append("{0}".format(str(count).rjust(colwidth)))
			optypelist.append((perms_counts[totalstr], optype_line))

		sorted_optypelist = reversed(sorted(optypelist, key=lambda x:x[0]))
		for (c, optype_line) in sorted_optypelist:
			# Calculate percentages now:
			optype_line[2] = ("{0:{w}.2f}%").format(
				c / proc_totalvmas * 100, w=colwidth-1)
			s = '\t'.join(optype_line)
			f.write("{}\n".format(s))

		totals = [totalstr.rjust(fcolwidth)]
		totals.append("{0}".format(
			str(total_counts[totalstr]).rjust(colwidth)))
		totals.append("100%".rjust(colwidth))
		for perms_key in PERMS_KEYS:
			totals.append("{0}".format(
				str(total_counts[perms_key]).rjust(colwidth)))
		percents = [percentstr.rjust(fcolwidth)]
		percents.append("100%".rjust(colwidth))
		percents.append("100%".rjust(colwidth))
		for perms_key in PERMS_KEYS:
			percents.append("{0:{w}.2f}%".format(
				total_counts[perms_key] / total_counts[totalstr] * 100,
				w=colwidth-1))
		f.write("{}\n".format('\t'.join(totals)))
		f.write("{}\n".format('\t'.join(percents)))
	
	f.close()
	return

FIRSTCOLWIDTH = [55, 111]

def query_perms_by_modulestack(outputdir, proc_groups, whichtable):
	return query_perms_by_module(outputdir, proc_groups,
		whichtable, 'stack')

def query_perms_by_modulecat(outputdir, proc_groups, whichtable):
	return query_perms_by_module(outputdir, proc_groups,
		whichtable, 'category')

def query_perms_by_fn_full(outputdir, proc_groups, whichtable):
	return query_perms_by_module(outputdir, proc_groups,
		whichtable, 'fn_full')

# selector arg: filter/sort modules by their full "callstack" used
# (non-overlapping query), or by using the "sophisticated category" method
# (which is an "overlapping" query)?
def query_perms_by_module(outputdir, proc_groups, whichtable,
		selector):
	tag = "query_perms_by_module"

	if selector == 'stack':
		fname = "{0}/perms_by_modulestack".format(outputdir)
		query_fn = lazy_module_query_fn
		fcolwidth = FIRSTCOLWIDTH[1]
	elif selector == 'category':
		fname = "{0}/perms_by_modulecat".format(outputdir)
		query_fn = sophisticated_module_query_fn
		fcolwidth = FIRSTCOLWIDTH[0]
	elif selector == 'fn_full':
		fname = "{0}/perms_by_fn_full".format(outputdir)
		query_fn = lazy_fn_query_fn
		fcolwidth = FIRSTCOLWIDTH[1]
	else:
		print_error(tag, ("invalid selector: {}").format(
			selector))
		return
	
	f = open(fname, 'w')
	colwidth = 7
	write_vim_modeline_nowrap(f)

	# Keep track of header and line for each module as a list,
	# then join together later to form output string.
	totalstr = 'TOTAL'   # leading space helps with LibreOffice import...
	percentstr = 'Percent'
	header = ["Module".rjust(fcolwidth)]
	header.append("{0}".format(totalstr.rjust(colwidth)))
	header.append("{0}".format(percentstr.rjust(colwidth)))
	for perms_key in PERMS_KEYS:
		header.append("{0}".format(perms_key.rjust(colwidth)))
	f.write("Counts of vmas with various permissions, by process + "
		"module\n")
	total_counts = {}

#	for proc_info in proc_tracker.get_all_process_infos():
	for proc_group in proc_groups:
		root_proc = proc_group[0]
		(module_map, proc_totalvmas) = query_vmas_grouped(proc_group,
			query_fn, whichtable)

		# Skip processes that don't have any vmas in their vmatable
		# or all_vmas tracker:
		if len(module_map) == 0:
			continue

		f.write("\n")
#		f.write("{0}-{1}\n".format(proc_info.get_progname(),
#			proc_info.get_pid()))
		f.write("{}\n".format(root_proc.name()))
		f.write("{}\n".format('\t'.join(header)))

		for perms_key in PERMS_KEYS:
			total_counts[perms_key] = 0
		total_counts[totalstr] = 0

		modulelist = []
		for (module, vmalist) in module_map.items():
			# First, get counts and totals for this module:
			def perms_hash_fn(vma):
				return [vma.perms_key]
			(module_perms_map, meh) = construct_dict_from_list(
				vmalist, perms_hash_fn)
			perms_counts = {totalstr: 0}
			for (perms_key, vmas) in module_perms_map.items():
				perms_counts[perms_key]  = len(vmas)
				perms_counts[totalstr]  += len(vmas)
				total_counts[perms_key] += len(vmas)
				total_counts[totalstr]  += len(vmas)

			# Now construct output string for this module, but
			# don't write it yet: save it in a list, which we'll
			# sort by total count and then write out in descending
			# order.
			# We can't calculate the percentages yet, since we don't
			# know the totals across all modules, so just insert
			# placeholders for now and go back and edit
			# module_line[2] later.
			#   Note: rpartition no longer needed thanks to
			#   process_userstack_events. Leading space helps when
			#   importing into LibreOffice.
			#   http://docs.python.org/3/library/string.html#format-examples
			module_line = [(" {0}".format(module)).rjust(fcolwidth)]
			module_line.append("{0}".format(
				str(perms_counts[totalstr]).rjust(colwidth)))
			module_line.append("{0:{w}.2f}%".format(0, w=colwidth-1))
			for perms_key in PERMS_KEYS:   # same order for all modules
				try:
					count = perms_counts[perms_key]
				except:
					count = 0
				module_line.append("{0}".format(str(count).rjust(colwidth)))
			modulelist.append((perms_counts[totalstr], module_line))

		sorted_modulelist = reversed(sorted(modulelist, key=lambda x:x[0]))
		for (c, module_line) in sorted_modulelist:
			# Calculate percentages now.
			# If querying by module "category": use proc_totalvmas, returned
			# from the initial query that was run to sort the modules for this
			# process, as the denominator, rather than total_counts[totalstr].
			# If the categories in that initial query can overlap, then
			# total_counts[totalstr] will double (or more) -count vmas,
			# but with overlapping categories we care about percentages
			# of just a single-count of all of the vmas (and the percentages
			# will add up to more than 100%).
			# If the categories in the initial query don't overlap (if
			# the initial query was for the full "module stack"), then
			# proc_totalvmas should equal total_counts[totalstr] anyway.
			module_line[2] = ("{0:{w}.2f}%").format(
				c / proc_totalvmas * 100, w=colwidth-1)
			s = '\t'.join(module_line)
			f.write("{}\n".format(s))

		totals = [totalstr.rjust(fcolwidth)]
		totals.append("{0}".format(
			str(total_counts[totalstr]).rjust(colwidth)))
		totals.append("100%".rjust(colwidth))
		for perms_key in PERMS_KEYS:
			totals.append("{0}".format(
				str(total_counts[perms_key]).rjust(colwidth)))
		percents = [percentstr.rjust(fcolwidth)]
		percents.append("100%".rjust(colwidth))
		percents.append("100%".rjust(colwidth))
		for perms_key in PERMS_KEYS:
			percents.append("{0:{w}.2f}%".format(
				total_counts[perms_key] / total_counts[totalstr] * 100,
				w=colwidth-1))
		
		# Skip totals and percentages at bottom for overlapping
		# categories, since totals don't really make sense.
		if selector in ['stack', 'fn_full']:
			f.write("{}\n".format('\t'.join(totals)))
			f.write("{}\n".format('\t'.join(percents)))
	
	f.close()
	return

def query_optype_by_modulestack(outputdir, proc_groups, whichtable):
	return query_optype_by_module(outputdir, proc_groups,
		whichtable, 'stack')

def query_optype_by_modulecat(outputdir, proc_groups, whichtable):
	return query_optype_by_module(outputdir, proc_groups,
		whichtable, 'category')

def query_optype_by_fn_full(outputdir, proc_groups, whichtable):
	return query_optype_by_module(outputdir, proc_groups,
		whichtable, 'fn_full')

def query_optype_by_component(outputdir, proc_groups, whichtable):
	return query_optype_by_module(outputdir, proc_groups,
		whichtable, 'component')

def query_optypes_startswith(outputdir, proc_groups, whichtable):
	query_optype_by_module(outputdir, proc_groups, whichtable, 'startswithfn')
	return

def query_optypes_endswith(outputdir, proc_groups, whichtable):
	query_optype_by_module(outputdir, proc_groups, whichtable, 'endswithfn')
	return

def query_optypes_firefox(outputdir, proc_groups, whichtable):
	query_optype_by_module(outputdir, proc_groups, whichtable, 'firefox')
	return

def startswith_fn_query(vma):
	fnlist = vma.creator_fn.split(fn_sep)
	return [fnlist[0]]
def endswith_fn_query(vma):
	fnlist = vma.creator_fn.split(fn_sep)
	return [fnlist[-1]]

# This function is very similar to query_perms_by_module... can they
# be combined?
def query_optype_by_module(outputdir, proc_groups, whichtable, selector):
	tag = "query_optype_by_module"

	if selector == 'stack':
		fname = "{0}/op_types_by_modulestack".format(outputdir)
		query_fn = lazy_module_query_fn
		fcolwidth = FIRSTCOLWIDTH[1]
	elif selector == 'category':
		fname = "{0}/op_types_by_modulecat".format(outputdir)
		query_fn = sophisticated_module_query_fn
		fcolwidth = FIRSTCOLWIDTH[0]
	elif selector == 'fn_full':
		fname = "{0}/op_types_by_fn_full".format(outputdir)
		query_fn = lazy_fn_query_fn
		fcolwidth = FIRSTCOLWIDTH[1]
	elif selector == 'component':
		fname = "{0}/op_types_by_component".format(outputdir)
		query_fn = determine_component_query_fn
		fcolwidth = FIRSTCOLWIDTH[1]
	elif selector == 'startswithfn':
		fname = "{0}/op_types_startswith_fn".format(outputdir)
		query_fn = startswith_fn_query
		fcolwidth = FIRSTCOLWIDTH[1]
	elif selector == 'endswithfn':
		fname = "{0}/op_types_endswith_fn".format(outputdir)
		query_fn = endswith_fn_query
		fcolwidth = FIRSTCOLWIDTH[1]
	elif selector == 'firefox':
		fname = "{0}/op_types_firefox".format(outputdir)
		query_fn = determine_component_firefox
		fcolwidth = FIRSTCOLWIDTH[1]
	else:
		print_error(tag, ("invalid selector: {}").format(selector))
		return
	
	f = open(fname, 'w')
	colwidth = 14
	write_vim_modeline_nowrap(f)

	# Keep track of header and line for each module as a list,
	# then join together later to form output string.
	totalstr = 'TOTAL'   # leading space helps with LibreOffice import...
	percentstr = 'Percent'
	header = ["Module".rjust(fcolwidth)]
	header.append("{0}".format(totalstr.rjust(colwidth)))
	header.append("{0}".format(percentstr.rjust(colwidth)))
	for op_type in VMA_OP_TYPES:
		header.append("{0}".format(op_type.rjust(colwidth)))
	f.write("Counts of vmas created via each operation type, "
		"by process + module\n")
	total_counts = {}

	for proc_group in proc_groups:
		root_proc = proc_group[0]
		(module_map, proc_totalvmas) = query_vmas_grouped(proc_group,
			query_fn, whichtable)

		# Skip processes that don't have any vmas in their vmatable
		# or all_vmas tracker:
		if len(module_map) == 0:
			continue

		f.write("\n")
		f.write("{}\n".format(root_proc.name()))
		f.write("{}\n".format('\t'.join(header)))

		for op_type in VMA_OP_TYPES:
			total_counts[op_type] = 0
		total_counts[totalstr] = 0

		modulelist = []
		for (module, vmalist) in module_map.items():
			def op_hash_fn(vma):
				return [vma.vma_op]
			(module_ops_map, meh) = construct_dict_from_list(
				vmalist, op_hash_fn)
			op_counts = {totalstr: 0}
			for (op_type, vmas) in module_ops_map.items():
				op_counts[op_type]      = len(vmas)
				op_counts[totalstr]    += len(vmas)
				total_counts[op_type]  += len(vmas)
				total_counts[totalstr] += len(vmas)

			# Now construct output string for this module, but
			# don't write it yet: save it in a list, which we'll
			# sort by total count and then write out in descending
			# order.
			# We can't calculate the percentages yet, since we don't
			# know the totals across all modules, so just insert
			# placeholders for now and go back and edit
			# module_line[2] later.
			#   Note: rpartition no longer needed thanks to
			#   process_userstack_events. Leading space helps when
			#   importing into LibreOffice.
			#   http://docs.python.org/3/library/string.html#format-examples
			module_line = [(" {0}".format(module)).rjust(fcolwidth)]
			module_line.append("{0}".format(
				str(op_counts[totalstr]).rjust(colwidth)))
			module_line.append("{0:{w}.2f}%".format(0, w=colwidth-1))
			for op_type in VMA_OP_TYPES:   # same order for all modules
				try:
					count = op_counts[op_type]
				except:
					count = 0
				module_line.append("{0}".format(str(count).rjust(colwidth)))
			modulelist.append((op_counts[totalstr], module_line))

		sorted_modulelist = reversed(sorted(modulelist, key=lambda x:x[0]))
		for (c, module_line) in sorted_modulelist:
			# Calculate percentages now: see note in query_perms_by_modulecat
			# for why we use proc_totalvmas here.
			module_line[2] = ("{0:{w}.2f}%").format(
				c / proc_totalvmas * 100, w=colwidth-1)
			s = '\t'.join(module_line)
			f.write("{}\n".format(s))

		totals = [totalstr.rjust(fcolwidth)]
		totals.append("{0}".format(
			str(total_counts[totalstr]).rjust(colwidth)))
		totals.append("100%".rjust(colwidth))
		for op_type in VMA_OP_TYPES:
			totals.append("{0}".format(
				str(total_counts[op_type]).rjust(colwidth)))
		percents = [percentstr.rjust(fcolwidth)]
		percents.append("100%".rjust(colwidth))
		percents.append("100%".rjust(colwidth))
		for op_type in VMA_OP_TYPES:
			percents.append("{0:{w}.2f}%".format(
				total_counts[op_type] / total_counts[totalstr] * 100,
				w=colwidth-1))
	
		# Skip totals and percentages at bottom for overlapping
		# categories, since totals don't really make sense.
		if selector in ['stack', 'fn_full']:
			f.write("{}\n".format('\t'.join(totals)))
			f.write("{}\n".format('\t'.join(percents)))

	f.close()
	return

def proc_group_to_tsv(proc_group):
	#return ','.join(list(map(lambda proc: proc.name(), proc_group)))
	return '\t'.join(list(map(lambda proc: proc.name(), proc_group)))

# Set outputdir to None if you do not want to write out a process_groups
# file.
# Returns: the proc_groups data structure on success, or None on error.
def create_save_process_groups(outputdir, proc_tracker, group_multiproc,
		target_pids):
	tag = 'create_save_process_groups'

	skip_partial_processes = False
	proc_groups = group_processes(proc_tracker, group_multiproc,
			skip_partial_processes, target_pids)
	if proc_groups is None:
		print_error(tag, ("group_processes failed").format())
		return None

	if outputdir:
		success = write_process_groups(outputdir, proc_groups)
		if not success:
			return None

	if False:
		test_proc_groups = read_process_groups(outputdir, False, False)
		print(("PROCESS_GROUPS: read back test_proc_groups="
			"{}").format(test_proc_groups))
		test_proc_groups = read_process_groups(outputdir, True, True)
		print(("PROCESS_GROUPS: read back test_proc_groups="
			"{}").format(test_proc_groups))
		test_proc_groups = read_process_groups(outputdir, True, False)
		print(("PROCESS_GROUPS: read back test_proc_groups="
			"{}").format(test_proc_groups))
		test_proc_groups = read_process_groups(outputdir, False, True)
		print(("PROCESS_GROUPS: read back test_proc_groups="
			"{}").format(test_proc_groups))

	return proc_groups

# Writes the process groups in proc_groups to a TSV file in the output
# dir.
def save_process_groups_tsv(outputdir, proc_groups):
	tag = 'save_process_groups_tsv'

	fname = "{}/{}".format(outputdir, proc_groups_fname)
	if os.path.exists(fname):
		print_unexpected(True, tag, ("process_groups file {} already "
			"exists - will overwrite it!").format(fname))
	f = open(fname, 'w')
	if not f:
		print_error_exit(tag, ("failed to open {} for writing").format(
			fname))
	
	for proc_group in proc_groups:
		f.write("{}\n".format(proc_group_to_tsv(proc_group)))

	f.close()
	return

# Iterates through the proc_groups and for each group (all processes in the
# group are grouped together here), outputs a TSV file containing the
# data from the all_vmas structure tracked during the analysis.
# The vmas will be sorted by their TIMESTAMP.
def save_all_vmas(outputdir, proc_groups):
	tag = 'save_all_vmas'

	for group in proc_groups:
		group_vmalist = get_group_vmalist(group, 'all_vmas')
		sorted_vmalist = sorted(group_vmalist, key=lambda vma: vma.timestamp)
		#if DEBUG:
		#	for vma in sorted_vmalist:
		#		print_debug(tag, ("{} {}\t - {}").format(group[0].name(),
		#			vma.timestamp, vma.to_str_maps_format()))

		# Write one file per proc_group root:
		vmas_fname = "{}/{}-{}".format(outputdir, group[0].name(),
			saved_vmas_fname)
		if os.path.exists(vmas_fname):
			print_unexpected(True, tag, ("file already exists: {}").format(
				vmas_fname))
		
		vmas_f = open(vmas_fname, 'w')
		for vma in sorted_vmalist:
			line = vma.marshal_tsv()
			vmas_f.write("{}\n".format(line))
		vmas_f.close()

	return

# Returns a list of sublists, where each sublist is a group of one or
# more processes from the proc_tracker. If group_multiproc is True then
# processes forked off of a root process will be placed in the root
# process' group. If skip_partial_processes is True, then any processes
# for which a fork was not observed during the trace will not be put
# into any group.
#   Note: the meaning of skip_partial_processes has been slightly
#   adjusted: we will *not* skip a process for which we have seen an
#   exec but not a fork (see above for explanation of when this may
#   happen - grep for 'saw_exec').
# The root process for a group is guaranteed to be the first item in a sublist.
# New arg: target_pids: list of pids that we really care about (e.g.
# as noted by the script / user that executed the application trace).
# If this list is non-empty, then the final step in this method will
# be to prune any process groups whose pids/tgids are not found in the
# target_pids list.
# Or, returns None on error.
def group_processes(proc_tracker, group_multiproc, skip_partial_processes,
		target_pids):
	tag = 'group_processes'

	debughere = False

	if target_pids and len(target_pids) > 0:
		target = True
		print_debug2(debughere, tag, ("will only add processes "
			"found in target_pids "
			"list to proc_groups: {}").format(target_pids))
	else:
		target = False
		print_debug2(debughere, tag, ("target_pids list is empty").format())

	proc_groups = []
	if group_multiproc:
		for proc_info in proc_tracker.get_all_process_infos():
			sublist = []
			if target and (proc_info.get_pid() not in target_pids):
				print_debug2(debughere, tag, ("{} not in target_pids, "
					"so won't "
					"add to proc_groups unless it's a child of a "
					"targeted rootproc").format(proc_info.name()))
			elif proc_info.get_is_rootproc():
				# Important that first entry in the sublist is the root!
				parent = proc_info
				sublist.append(parent)
				child_proc_infos = proc_tracker.get_child_process_infos(
						parent.get_pid())
				if child_proc_infos is None:
					print_error_exit(tag, ("get_child_process_infos "
						"failed for {}").format(parent.name()))
				for child in child_proc_infos:
					sublist.append(child)
			else:
				if proc_info.get_tgid_for_stats() != proc_info.get_pid():
					# Work is already done (or will be done) when root
					# process is encountered.
					print_debug2(debughere, tag, ("process {} is not "
						"a rootproc, "
						"but should be grouped with \"parent\" "
						"{}").format(proc_info.name(),
						proc_tracker.get_process_info(
							proc_info.get_tgid_for_stats()).name()))
				elif skip_partial_processes:
					# If process is non-root and doesn't have a tgid-for-
					# stats set, then we must not have seen its fork
					# or its exec!
					if proc_info.saw_fork or proc_info.saw_exec:
						print_error_exit(tag, ("{}: saw_fork={} and "
							"saw_exec={}, but don't expect either to "
							"be set here!").format(
							proc_info.name(), proc_info.saw_fork,
							proc_info.saw_exec))
					print_debug2(debughere, tag, ("skip_partial_processes is "
						"True, so not adding {} to list of processes "
						"to analyze - we shouldn't care about this "
						"process").format(proc_info.name()))
				else:
					sublist.append(proc_info)
					print_debug2(debughere, tag, ("processing isolated "
						"process {} "
						"on its own").format(proc_info.name()))
			
			if len(sublist) > 0:
				print_debug2(debughere, tag, ("adding process group to "
					"proc_groups: {}").format(
					list(map(lambda proc: proc.name(), sublist))))
				proc_groups.append(sublist)

	else:
		# Build a list of lists, where each sub-list holds just a
		# single proc_info.
		for proc_info in proc_tracker.get_all_process_infos():
			if target and (proc_info.get_pid() not in target_pids):
				print_debug2(debughere, tag, ("{} not in target_pids and "
					"group_multiproc is false, so definitely won't "
					"add to proc_groups").format(proc_info.name()))
			elif (skip_partial_processes and
					not proc_info.have_full_info()):
				print_debug2(debughere, tag, ("skip_partial_processes is "
					"True while both saw_fork={} and saw_exec={}, so "
					"not adding {} to list of processes "
					"to analyze - we shouldn't care about this "
					"process").format(proc_info.name(),
					proc_info.saw_fork, proc_info.saw_exec))
			else:
				print_debug2(debughere, tag, ("adding process group to "
					"proc_groups: {}").format([proc_info.name()]))
				proc_groups.append([proc_info])

	return proc_groups

# Checks if we care about events for the specified test_tgid, based
# on target_pids and the process hierarchy information tracked in
# the proc_tracker.
# Based on earlier "do_we_care()" method.
# Returns a tuple: (is the process relevant; the tgid to be used for
#   statistics accounting (i.e. when target_pids and group_multiproc
#   are active)). Note that the latter may still be necessary even
#   when the former is False, if skip_irrelevant_processes is not set.
#   For global events, (True, None) is returned.
def is_relevant(proc_tracker, group_multiproc, target_pids, test_tgid,
		trace_event_type, task):
	tag = 'is_relevant'

	debughere = False

	# We always care about certain "global" events that are not
	# associated with any particular pid:
	if trace_event_type in GLOBAL_EVENT_TYPES:
		print_debug2(debughere, tag, ("trace_event_type {} is "
			"global, returning (True, None)").format(
			trace_event_type))
		return (True, None)

	proc_info = proc_tracker.get_process_info(test_tgid)
	if not proc_info:
		print_unexpected(True, tag, ("get_process_info({}) "
			"failed").format(test_tgid))
	tgid_for_stats = proc_info.get_tgid_for_stats()
	if tgid_for_stats is None:
		# Currently, tgid_for_stats is always initialized to be the
		# same as proc_info.pid, so even for processes whose fork or
		# exec we haven't seen, they will still have a valid
		# tgid_for_stats.
		print_unexpected(True, tag, ("expect tgid_for_stats to always be "
			"set by this point!").format())
	elif tgid_for_stats == 0:
		if task != '<idle>':
			print_unexpected(True, tag, ("got tgid_for_stats=0, but "
				"process name is {} and task is {}").format(
				proc_info.name(), task))
		else:
			# For some reason, I never saw events from the "<idle>-0"
			# process until a trace from stjohns. Because these events
			# were pte_at events (without any vma events before them),
			# the proc_info does not have its progname set (because 
			# do_common_vma_processing() has never been called), so
			# we have to examine the 'task' from the trace line directly.
			print_debug(tag, ("got tgid_for_stats=0 - "
				"trace event for idle process {}, returning "
				"not-relevant right now").format(task))
			return (False, 0)

	if target_pids and len(target_pids) > 0:
		print_debug2(debughere, tag, ("target_pids: {}").format(target_pids))
		if test_tgid in target_pids:
			print_debug2(debughere, tag, ("test_tgid {} in target_pids, "
				"so definitely relevant").format(test_tgid))
			if test_tgid != tgid_for_stats:
				print_error_exit(tag, ("test_tgid {} doesn't equal "
					"tgid_for_stats {} - is this ever expected based "
					"on how target_pids list works?!").format(
					test_tgid, tgid_for_stats))
			return (True, test_tgid)
		elif tgid_for_stats in target_pids:
			# tgid_for_stats has already accounted for group_multiproc
			print_debug2(debughere, tag, ("ancestor process "
				"(tgid_for_stats={}) is in target_pids list, so this "
				"process' event is relevant").format(tgid_for_stats))
			return (True, tgid_for_stats)
		else:
			print_debug2(debughere, tag, ("neither test_tgid {} nor "
				"tgid_for_stats {} is in target_pids list, so this "
				"process' events are not relevant").format(
				test_tgid, tgid_for_stats))
			return (False, tgid_for_stats)

	else:
		# Not targeting any specific processes, but may still need to
		# do multiproc grouping etc.
		print_error_exit(True, tag, ("this code path is untested "
			"since we now kind of expect target_pids to always "
			"be set - remove this assert and double-check output"
			"!").format())
		skip_partial_processes = True
		if (skip_partial_processes and not proc_info.have_full_info()):
			print_debug2(debughere, tag, ("skip_partial_processes "
				"is True but we don't have full information for "
				"process {}, so it's not relevant").format(
				proc_info.name()))
			return (False, tgid_for_stats)
		elif group_multiproc:
			print_debug2(debughere, tag, ("we care about all processes "
				"at this point and group_multiproc is True, so using "
				"tgid_for_stats {}").format(tgid_for_stats))
			return (True, tgid_for_stats)
		else:
			print_debug2(debughere, tag, ("we care about all processes "
				"at this point but group_multiproc is False, so using "
				"just the test_tgid {}").format(test_tgid))
			return (True, test_tgid)
	
	print_error_exit(tag, 'unreachable')
	return (True, -1)

# Checks if we care about events for the specified test_tgid, based
# on target_pids and the process hierarchy information tracked in
# the proc_tracker. If we do care, then this method returns the
# tgid that should be used for stats / accounting / plotting purposes
# (which may be a parent / grandparent / etc. process of the target_tgid
# if group_multiproc is True). If we don't care, then None is returned.
def do_we_care(proc_tracker, group_multiproc, skip_partial_processes,
		target_pids, test_tgid):
	tag = 'do_we_care'

	debughere = False

	proc_info = proc_tracker.get_process_info(test_tgid)
	if not proc_info:
		print_error_exit(tag, ("get_process_info({}) failed").format(
			test_tgid))
	tgid_for_stats = proc_info.get_tgid_for_stats()
	if not tgid_for_stats:
		# Currently, tgid_for_stats is always initialized to be the
		# same as proc_info.pid, so even for processes whose fork or
		# exec we haven't seen, they will still have a valid
		# tgid_for_stats.
		print_error_exit(tag, ("expect tgid_for_stats to always be "
			"set by this point!").format())

	if target_pids and len(target_pids) > 0:
		print_debug2(debughere, tag, ("will only care about processes "
			"found in "
			"the target_pids list {}").format(target_pids))
		if test_tgid in target_pids:
			print_debug2(debughere, tag, ("test_tgid {} in target_pids, "
				"so we "
				"do care about this event").format(test_tgid))
			if test_tgid != tgid_for_stats:
				print_error_exit(tag, ("test_tgid {} doesn't equal "
					"tgid_for_stats {} - is this ever expected based "
					"on how target_pids list works?!").format(
					test_tgid, tgid_for_stats))
			return test_tgid
		elif tgid_for_stats in target_pids:
			# tgid_for_stats has already accounted for group_multiproc
			print_debug2(debughere, tag, ("ancestor process "
				"(tgid_for_stats={}) is "
				"in target_pids list, so we do care about this "
				"event").format(tgid_for_stats))
			return tgid_for_stats
		else:
			print_debug2(debughere, tag, ("neither test_tgid {} nor "
				"tgid_for_stats "
				"{} is in target_pids list, so we don't care about "
				"this event").format(test_tgid, tgid_for_stats))
			return None

	else:
		# Not targeting any specific processes, but may still need to
		# do multiproc grouping etc.
		if (skip_partial_processes and not proc_info.have_full_info()):
			print_debug2(debughere, tag, ("skip_partial_processes is True "
				"but we don't have full information for this process, "
				"so we don't care").format())
			return None
		elif group_multiproc:
			print_debug2(debughere, tag, ("we care about all processes "
				"at this "
				"point and group_multiproc is True, so using "
				"tgid_for_stats {}").format(tgid_for_stats))
			return tgid_for_stats
		else:
			print_debug2(debughere, tag, ("we care about all processes "
				"at this "
				"point but group_multiproc is False, so using just "
				"the test_tgid {}").format(test_tgid))
			return test_tgid
	
	print_error_exit(tag, 'unreachable')
	return

# There are a few "categories" of queries that we want to run at
# particular points in time:
#   "Checkpoint" queries: when we care about only what has
#     happened / changed since the last checkpoint.
#   "Current state" queries: when we want to output the current
#     state of the process (typically just its vmatable).
#   "Cumulative" queries: when we want to output everything that
#     has happened in the process up to this point (i.e. its
#     all_vmas data).
# Use the queries_to_run argument to select which set of queries
# to run below.
def run_queries(outputdir, proc_tracker, queries_to_run,
		group_multiproc, target_pids):
	tag = "run_queries"

	# Is there a sensible, consistent way to handle the group_multiproc
	# flag here? Right now, every one of these queries contains this
	# logic:
	#    for proc_info in proc_tracker.get_all_process_infos(): ...
	# So, the proc_tracker could be replaced with a *list* of proc_infos,
	# where each proc_info is already "grouped" if group_multiproc is
	# true. Is there a clear way to group together two or more proc_infos
	# into one proc_info?
	#   The vmas associated with each proc_info are kept in three
	#   dicts: vmatable, all_vmas, and cp_vmas. The key for each of
	#   these is the vma start-address; vmatable holds a single vma
	#   as its value, but all_vmas and cp_vmas already hold *lists*
	#   of vmas as their values! So it would be easy to combine all_vmas
	#   and cp_vmas together - it doesn't appear that vmatables can
	#   be easily combined, but for a query that's inspecting a vmatable,
	#   would it want multiple processes to be combined anyway? I
	#   guess this might be desirable... but for now, implement a
	#   combining method that combines two proc_infos together by
	#   appending their all_vmas and cp_vmas value lists, and just
	#   take the "source" vmatable for now. Later, the vmatable can
	#   also be converted to hold *lists* of vmas...
	#
	# Second thought: for most queries, the *keys* of the vmatable /
	# all_vmas / cp_vmas are discarded anyway, and the vmas are combined
	# into a huge list (see the query_vmas -> query_vmatable / 
	# query_all_vmas / query_cp_vmas path). So, if we push the COMBINING
	# logic down into these methods, then it seems pretty easy to build
	# the big list no matter which initial dicts we're using.
	# However, I think that we can still put the GROUPING logic HERE:
	# since each query is iterating through the proc_tracker anyway,
	# we can switch out the proc_tracker and switch in a new input
	# which is a list of lists: each sub-list is a set of proc_infos
	# that should be grouped together! The query functions can then
	# iterate over this instead of iterating over the proc_tracker,
	# passing the grouped proc_info lists to the query_vmas method,
	# which will know that it's supposed to combine them. I think this
	# will work...
	#
	# Great, this second approach (putting the grouping logic here, but
	# the combining work down lower) seems to be working. Minor drawback:
	# if run_queries is called repeatedly AT THE SAME POINT IN TIME (e.g.
	# at the very end of the analysis), then we're going to perform both
	# the grouping and the combining steps repeatedly.
	#   Oh well...

	proc_groups = create_save_process_groups(outputdir, proc_tracker,
			group_multiproc, target_pids)
	if not proc_groups:
		print_error(tag, ("create_save_process_groups() failed"))
		return
	elif len(proc_groups) == 0:
		print_error(tag, ("len(proc_groups) is 0, returning"))
		return

	# Items in this list are function pointers which take an output
	# directory and the proc_tracker that was used for the simulation.
	# They also take a third argument, a string to indicate whether
	# the query should be run on the process' current vmatables or
	# their all_vmas trackers.
	# And a fourth argument: whether or not these queries should group
	# together multi-process proc_infos.
	# These functions should create a new file, run their query on
	# the process_infos in the proc_tracker, write the query output
	# to the file, then close the file before returning.
	checkpoint_queries = [
		#"query_perms_by_modulestack",
		#"query_perms_by_modulecat",
		#"query_perms_by_fn_full",
		#"query_optype_by_modulestack",
		#"query_optype_by_modulecat",
		#"query_optype_by_fn_full",
		#'query_perms_by_optype',
		#"query_mprotect_sizes",
	]
	current_queries = [
		#"query_module_segsizes",
		#"query_segsizes",
		#"query_vaspace_maps",
	]
	cumulative_queries = [
		#"query_module_segment_ops",
		#"query_fn_segment_ops",
		#"query_module_segsizes",
		#"query_segsizes",
		#"query_perms_by_modulestack",
		#"query_perms_by_modulecat",
		#"query_perms_by_fn_full",
		#"query_optype_by_modulestack",
		#"query_optype_by_modulecat",
		#"query_optype_by_fn_full",
		#'query_optype_by_component',
		#'query_optypes_startswith',
		#'query_optypes_endswith',
		#'query_optypes_firefox',
		#'query_perms_by_optype',
		#"query_mprotect_sizes",
	]
	if queries_to_run == 'checkpoint':
		queryset = checkpoint_queries
		whichtable = 'cp_vmas'
	elif queries_to_run == 'current':
		queryset = current_queries
		whichtable = 'vmatable'
	elif queries_to_run == 'cumulative':
		queryset = cumulative_queries
		whichtable = 'all_vmas'
	else:
		print_error_exit(tag, ("invalid queries_to_run arg: "
			"{}").format(queries_to_run))

	# Cool: execute method given string
	#   http://bytes.com/topic/python/answers/801884-given-string-execute-
	#   function-same-name
	#   http://stackoverflow.com/questions/3061/calling-a-function-from-a-
	#   string-with-the-functions-name-in-python
	#   http://docs.python.org/3/library/functions.html#getattr
	#import __main__
	if __name__ == '__main__':
		import __main__
		module = __main__
	else:
		import analyze_trace
		module = analyze_trace
	for query in queryset:
		print_debug(tag, ("running query {0}").format(query))
		#q = getattr(__main__, query)
		q = getattr(module, query)
		q(outputdir, proc_groups, whichtable)

	return proc_groups

def make_vaspace_plots(proc_group, timestamp, current_appname,
		app_pid, descr, outputdir):
	tag = 'make_vaspace_plots'

	num_processes = len(proc_group)

	# We'll construct the VA-space plots right here + now, in their
	# own special directory. Use descr when naming the directory
	# so that we won't interfere with other points in time during
	# this analysis run.
	vaspace_dir = "{}/vaspace_plots-{}".format(outputdir, descr)
	print_debug(tag, ("saving vaspace plots in {}").format(vaspace_dir))
	try:
		os.mkdir(vaspace_dir)
	except FileExistsError:
		print_warning(tag, ("vaspace_plots directory with name "
			"{} already exists! Will delete it and re-create it").format(
			vaspace_dir))
		shutil.rmtree(vaspace_dir)
		os.mkdir(vaspace_dir)

	# For the virtual address space plots, rather than collecting
	# the active_vmas for all of the processes in the group, we
	# want to create one plot per process.
	proc_num = 0
	for proc in proc_group:
		proc_num += 1
		single_proc_group = [proc]
		active_vmas = get_active_vmas(single_proc_group, timestamp,
				call_ignore_vmas=False)
		if len(active_vmas) == 0:
			continue

		# Create a new output directory for each process, and a
		# new pdffile for each:
		proc_outputdir = "{}/{}".format(vaspace_dir, proc.name())
		try:
			os.makedirs(proc_outputdir)
		except FileExistsError:
			print_unexpected(True, tag, ("proc_outputdir {} already "
				"exists, but shouldn't we have just created the "
				"vaspace_plots dir?").format(proc_outputdir))
		#proc_pdf_name = "{}/vaspace_plots".format(proc_outputdir)
		#proc_pdf = plots.new_pdffile(proc_pdf_name)

		active_vmas_to_maps_file(active_vmas, proc_outputdir, descr)

		#plotname_suffix = "{}".format(descr)
		plotname_suffix = ''   # use descr in directory name now
		vaspace_plot = plot_vaspace.new_vaspace_plot(
				plotname_suffix, proc_outputdir, proc_num,
				num_processes)
		#vaspace_plot.add_pdffile(proc_pdf)

		vaspace_plot.process_active_vmas(active_vmas, proc.progname,
				proc.pid)

		vaspace_plot.complete()
		#proc_pdf.close()

	return

# Does analysis and table/graph generation for the specified point in
# time during the trace. 
# Returns: a list containing any newly created multiapp_plot objects.
def analyze_point_in_time(analysisdir, outputdir, proc_group,
		current_appname, app_pid, timestamp, descr, process_userstacks):
	tag = 'analyze_point_in_time'

	# IMPORTANT: when creating new directories in this method or any
	# method that it calls, the *descr* must be included in the
	# directory name, because this method may be called repeatedly
	# for different points in time! So if we remove and re-create
	# directories here, we may remove a directory that was just
	# created for a previous point in time.

	newplots = []

	# Don't set call_ignore_vmas to True here - let each plot
	# decide if it wants to ignore shared libs etc. when it
	# processes the active_vmas!
	active_vmas = get_active_vmas(proc_group, timestamp,
			call_ignore_vmas=False)
	num_processes = len(proc_group)
	print_debug(tag, ("at point-in-time \"{}\", {} had {} processes "
		"active with {} total vmas (timestamp {})").format(
		descr, current_appname, num_processes, len(active_vmas),
		timestamp))

	# This file, which will go in the "generate-analysis" subdir,
	# will combine all of the vmas across all processes - it won't
	# resemble an actual valid maps file, because vmas may overlap!
	# We output per-process maps files when we output vaspace plots
	# below.
	active_vmas_to_maps_file(active_vmas, outputdir,
			"entireprocgroup-{}".format(descr))

	# Now, "deduplicate" the active_vmas list: we do this to eliminate
	# the vmas that are duplicated across processes belonging to
	# the same application (the same proc_group above) are not counted
	# more than once.
	#   TODO: calling deduplicate_active_vmas() here probably isn't
	#   the most efficient way to go about this, and it also may not
	#   be correct - we want to track the "deduplicated" vmas while
	#   the entire trace is being processed, so that we can determine
	#   the point-in-time while deduplicated vmas are already being
	#   excluded!
	#     This seems like it will involve tracking even more fork
	#     information during the trace - ugh :(
	#     However, I've already written other code that ignores vmas
	#     associated with shared libs and guard regions (which works
	#     while processing the trace intially, so it can be applied
	#     to all plots) - if we ignore all non-writeable shared libs
	#     and guard regions in those plots, how well does it approximate
	#     what the dedup code does here? I examined the difference
	#     in maps files before and after deduplicating here for apache,
	#     and it turns out that almost every single vma that was removed by
	#     the deduplication code was either a guard region or associated
	#     with a shared lib, so the approximation is almost exact. The
	#     only exceptions that I noticed were one vma that was r-xp but
	#     anonymous (10 of these for apache), and a few vmas for libs
	#     under /usr/lib that are
	#     "application specific" and so aren't excluded by the shared
	#     lib checking code right now.
	#       This turns out to be a big problem - if the "application-
	#       specific" libraries are not excluded for apache too, then
	#       there is a huge discrepancy in the final counts when dedup
	#       is used here and when *ignoring* is used for other plots!
	#       dedup here cuts 3500 vmas down to 1300, but ignoring only
	#       cuts 3500 vmas down to 1800! Most frequent offenders:
	#         /usr/lib/php5/.../*.so
	#         /usr/lib/apache2/modules/*.so
	#       Solution for now: add /usr/lib to the list of directories
	#       that are ignored!
	#     Another possible problem: apps that use shared files that are
	#     not for shared libs! (these apps include: office, cass, ffox,
	#     chrome, kbuild). We need to make sure to ignore these too,
	#     right? If we don't, then in multi-process apps (chrome in
	#     particular), we'll remove them from the deduplicated max-vmas
	#     column plot here, but we won't remove them from the time-series
	#     or other plots.
	#   TODO: fix this stupid giant mess!
	#
	# I validated that this code actually works by comparing
	# maps-entireprocgroup-max_vma_count to maps-deduplicated-max_vma_count
	# for apache: indeed, for certain vmas in the original active_vmas list,
	# they have up to 10 duplicates which are removed! Additionally, it
	# turns out that simply running "cat maps-entireprocgroup-max_vma_count
	# | uniq > maps-uniq" produces the same result as the deduplicated
	# maps file. Cool.
	deduplicated_active_vmas = deduplicate_active_vmas(active_vmas)
	active_vmas_to_maps_file(deduplicated_active_vmas, outputdir,
			"deduplicated-{}".format(descr))
	if len(deduplicated_active_vmas) != len(active_vmas):
		print_debug(tag, ("eliminated {} duplicate vmas from active "
			"vmas list").format(
			len(active_vmas) - len(deduplicated_active_vmas)))

	# This is useful for later analysis too (pass entries to
	# maps-entry-size.py script to get their size in pretty bytes):
	active_vmas_to_maps_file(deduplicated_active_vmas, outputdir,
			"deduplicated-{}-bysize".format(descr), sortby='size')

	#vmalist = active_vmas
	vmalist = deduplicated_active_vmas

	# Use a multiapp_plot to store the datapoints we'll calculate
	# here for OS overheads etc. Even though we don't have that
	# many datapoints, this will allow us to aggregate the data
	# across all apps and then plot or table it. Use analysisdir,
	# not outputdir, to store the series data files; pass the
	# descr arg to distinguish different points in time.
	if 'os_overheads_plot' in PlotList.point_in_time_plotlist:
		os_overheads_plot = plot_os_overheads.new_os_overheads_plot(
				descr, analysisdir)
		newplots.append(os_overheads_plot)

	if 'basepagesize_plot' in PlotList.point_in_time_plotlist:
		bps_plot = plot_os_overheads.new_basepagesize_plot(descr, analysisdir)
		newplots.append(bps_plot)

	if 'max_vmas_plot' in PlotList.point_in_time_plotlist:
		max_vmas_plot = plot_vmacount.new_max_vmas_cols_plot(
				descr, analysisdir)
		newplots.append(max_vmas_plot)

	if 'vma_categories_plot' in PlotList.point_in_time_plotlist:
		categories_cols_plot = plot_vmacount.new_categories_cols_plot(
				descr, analysisdir)
		newplots.append(categories_cols_plot)

	if 'vma_size_cols_plot' in PlotList.point_in_time_plotlist:
		vma_size_cols_plot = plot_vma_sizes.new_vma_size_cols_plot(
				descr, analysisdir)
		newplots.append(vma_size_cols_plot)

	if 'vma_size_cdf_plot' in PlotList.point_in_time_plotlist:
		vma_size_cdf_plot = plot_vma_sizes.new_vma_size_cdf_plot(
				descr, analysisdir)
		newplots.append(vma_size_cdf_plot)

	if 'vma_size_portion_plot' in PlotList.point_in_time_plotlist:
		vma_size_portion_plot = plot_vma_sizes.new_vma_size_portion_plot(
				descr, analysisdir)
		newplots.append(vma_size_portion_plot)

	# Process the active_vmas for each of these point-in-time plots:
	# each vma will be processed by the plot's processing method,
	# and any generated plot events will be consumed by the datafn.
	# For now, use current_appname passed down from main(), which
	# should be a prettier version of proc_group[0].progname when we're
	# only analyzing trace for one app at a time.
	for plot in newplots:
		plot.process_active_vmas(vmalist, current_appname, app_pid)

	# Handle VASpace plots separately:
	if 'vaspace_plots' in PlotList.point_in_time_plotlist:
		make_vaspace_plots(proc_group, timestamp, current_appname,
				app_pid, descr, outputdir)

	point_in_time_queries(outputdir, proc_group, current_appname,
			app_pid, timestamp, descr, vmalist,
			process_userstacks)

	return newplots

# Runs "queries" (text output, rather than plot output) against
# the active_vmas list.
def point_in_time_queries(outputdir, proc_group, current_appname,
		app_pid, timestamp, descr, active_vmas, process_userstacks):
	tag = 'point_in_time_queries'

	if not process_userstacks:
		print_debug(tag, ("process_userstacks False, so these queries "
			"will currently be empty, returning now"))
		return

	# TODO: organize this into methods, for now this is just a
	# hack-job to examine who's responsible for "small mappings"

	# Use descr in directory name to avoid interfering with any other
	# directories just created for other points in time.
	querydir = "{}/point-in-time-queries-{}".format(outputdir, descr)
	try:
		os.mkdir(querydir)
	except FileExistsError:
		# remove old dir, to avoid possible confusion if filenames
		# aren't exactly the same.
		print_warning(tag, ("querydir directory with name {} already "
			"exists! Will delete it and re-create it").format(
			querydir))
		shutil.rmtree(querydir)
		os.mkdir(querydir)

	# Pre-process the active_vmas list: create a new list that
	# only includes "small" vmas
	call_ignore_vmas = False
	ignore_guard_regions = False
	only_small_vmas = False
	small_vma_maxsize = PAGE_SIZE_4KB
	preprocessed_vmas = []
	for vma in active_vmas:
		if (not (only_small_vmas and vma.length != small_vma_maxsize) and
			not (call_ignore_vmas and call_ignore_vma(vma)) and
			not (ignore_guard_regions and vma.is_guard_region())):
			preprocessed_vmas.append(vma)
	print_debug(tag, ("preprocessed {} active_vmas down to {} "
		"vmas").format(len(active_vmas), len(preprocessed_vmas)))

	# This code inspired by query_optype_by_module()...
	#   Todo: coalesce these methods together?! Write come
	#     kind of generic table-printing method??
	if current_appname == 'ffox':
		query_fn = determine_component_firefox
	else:
		query_fn = determine_component_query_fn
	(module_map, mapped_vmas_count) = construct_dict_from_list(
			preprocessed_vmas, query_fn)

	if len(module_map) == 0:
		print_unexpected(False, tag, ("module_map is empty!").format())
		f.close()
		return

	fname = ("{}/small-vmas").format(querydir)
	f = open(fname, 'w')
	fcolwidth = FIRSTCOLWIDTH[1]
	colwidth = 14
	write_vim_modeline_nowrap(f)

	possible_sizes = ['4KB', '8KB', '<1MB', '1MB', '2MB', '>2MB']

	# Keep track of header and line for each module as a list,
	# then join together later to form output string.
	totalstr = 'TOTAL'
	percentstr = 'Percent'
	header = ["Module".rjust(fcolwidth)]
	header.append("{}".format(totalstr.rjust(colwidth)))
	header.append("{}".format(percentstr.rjust(colwidth)))
	for size in possible_sizes:
		header.append("{}".format(size.rjust(colwidth)))
	f.write(("VMA sizes created by module\n").format())

	f.write("\n")
	f.write("{}\n".format(current_appname))
	f.write("{}\n".format('\t'.join(header)))

	total_counts = {}
	for size in possible_sizes:
		total_counts[size] = 0
	total_counts[totalstr] = 0

	modulelist = []
	for (module, vmalist) in module_map.items():
		def size_hash_fn(vma):
			if vma.length == 4 * KB_BYTES:
				retval = '4KB'
			elif vma.length == 8 * KB_BYTES:
				retval = '8KB'
			elif (vma.length > 4 * KB_BYTES and
				vma.length < 1 * MB_BYTES):
				retval = '<1MB'
			elif vma.length == 1 * MB_BYTES:
				retval = '1MB'
			elif vma.length == 2 * MB_BYTES:
				retval = '2MB'
			else:
				retval = '>2MB'
			if retval not in possible_sizes:
				print_error_exit('size_hash_fn', ("inconsistency: "
					"retval {} not in possible_sizes {}").format(
					retval, possible_sizes))
			return [retval]

		(module_sizes_map, meh) = construct_dict_from_list(
				vmalist, size_hash_fn)
		size_counts = {totalstr: 0}
		for (size, vmas) in module_sizes_map.items():
			size_counts[size]       = len(vmas)
			size_counts[totalstr]  += len(vmas)
			total_counts[size]     += len(vmas)
			total_counts[totalstr] += len(vmas)

		module_line = [(" {}".format(module)).rjust(fcolwidth)]
		module_line.append("{}".format(
			str(size_counts[totalstr]).rjust(colwidth)))
		module_line.append("{:{w}.2f}%".format(0, w=colwidth-1))
		for size in possible_sizes:
			try:
				count = size_counts[size]
			except:
				count = 0
			module_line.append("{}".format(str(count).rjust(colwidth)))
		modulelist.append((size_counts[totalstr], module_line))

	sorted_modulelist = reversed(sorted(modulelist, key=lambda x:x[0]))
	for (c, module_line) in sorted_modulelist:
		# Calculate percentages now: see note in query_perms_by_modulecat
		# for why we use mapped_vmas_count ("proc_totalvmas") here.
		module_line[2] = ("{:{w}.2f}%").format(
			c / mapped_vmas_count * 100, w=colwidth-1)
		s = '\t'.join(module_line)
		f.write("{}\n".format(s))

	totals = [totalstr.rjust(fcolwidth)]
	totals.append("{}".format(
		str(total_counts[totalstr]).rjust(colwidth)))
	totals.append("100%".rjust(colwidth))
	for size in possible_sizes:
		totals.append("{}".format(
			str(total_counts[size]).rjust(colwidth)))
	percents = [percentstr.rjust(fcolwidth)]
	percents.append("100%".rjust(colwidth))
	percents.append("100%".rjust(colwidth))
	for size in possible_sizes:
		try:
			val = total_counts[size] / total_counts[totalstr] * 100
		except ZeroDivisionError:
			val = -1
		percents.append("{:{w}.2f}%".format(val, w=colwidth-1))
	
	# Not sure if these will make sense or not...
	f.write("{}\n".format('\t'.join(totals)))
	f.write("{}\n".format('\t'.join(percents)))
	
	f.close()

	return

def print_max_vm_stats(proc_groups):
	tag = 'print_max_vm_stats'

	for group in proc_groups:
		for p in group:
			# This should only print root/leader processes:
			if p.max_vma_count > 0 or p.max_vm_size > 0:
				print(("VM_STATS: {}: max vma count {} at {}, max "
					"vm size {} at {}. tgid_for_stats={}").format(
					p.name(), p.max_vma_count, p.max_vma_count_time,
					pretty_bytes(p.max_vm_size), p.max_vm_size_time,
					p.tgid_for_stats))

	return

# Handles plots and queries that should be performed at a certain
# point in time, but where the point in time isn't known until we've
# analyzed the entire trace (at the time of maximum vma count,
# maximum VM size, etc.).
# Returns: a list of new multiapp_plot objects that we've created here.
def point_in_time_plots(analysisdir, outputdir, proc_tracker,
		group_multiproc, target_pids, current_appname, process_userstacks):
	tag = 'point_in_time_plots'

	newplots = []

	# Similar to run_queries()...
	proc_groups = create_save_process_groups(None, proc_tracker,
			group_multiproc, target_pids)
	if not proc_groups or len(proc_groups) == 0:
		print_error(tag, ("create_save_process_groups() failed"))
		return

	#print_max_vm_stats(proc_groups)

	# Now, for every process group, we want to get a list of the
	# vmas that were "active" at every point-in-time that we care
	# about. The root_proc may stores these timestamps, but we
	# need to search for the vmas across all of the processes in
	# the group.
	# It seems like we care a little more about the point-in-time
	# for the maximum allocated VM size, rather than the maximum
	# count of vmas allocated. I don't expect to see much difference
	# between these though.
	for proc_group in proc_groups:
		root_proc = proc_group[0]

		if 'max_vma_count' in PlotList.points_in_time:
			max_vma_count_time = root_proc.max_vma_count_time
			point_plots = analyze_point_in_time(analysisdir, outputdir,
					proc_group, current_appname, root_proc.pid,
					max_vma_count_time, 'max_vma_count', process_userstacks)
			newplots += point_plots

		if 'max_vm_size' in PlotList.points_in_time:
			max_vm_size_time = root_proc.max_vm_size_time
			point_plots = analyze_point_in_time(analysisdir, outputdir,
					proc_group, current_appname, root_proc.pid,
					max_vm_size_time, 'max_vm_size', process_userstacks)
			newplots += point_plots
	
	return newplots

def output_tracked_processes(output_f, outputdir, trace_name,
		proc_tracker, group_multiproc, target_pids):
	tag = "output_tracked_processes"
	global mem_target_not_found

	# XXX: this method isn't very clean, could use a rewrite...

	# After going through entire trace file, write the set of vmas that we've
	# tracked to the output file.
	num_tracked = proc_tracker.num_tracked()
	output_f.write(("{0} processes tracked\n").format(num_tracked))
	output_f.write(("Memory operations that didn't hit in any known "
		"vma: {0}\n").format(mem_target_not_found))
	output_f.write(("\n").format())

	# At the end of the simulation / analysis, run all of the types of
	# queries: "checkpoint", "current", and "cumulative".
	for querytype in ['checkpoint', 'current', 'cumulative']:
		print_debug(tag, ("calling final queries of type {}").format(
			querytype))
		proc_groups = run_queries(outputdir, proc_tracker, querytype,
			group_multiproc, target_pids)
	
	# Finally, write data to disk that may be used for plotting later.
	# Currently, proc_groups is coming from the last call to run_queries
	# above; this is a little hacky, but if necessary we can make another
	# call to group_processes() here.
	# March 2014: are these still used?
	#save_process_groups_tsv(outputdir, proc_groups)
	#save_all_vmas(outputdir, proc_groups)

	return

def initialize(trace_fname, outputdir):
	tag = "initialize"

	try:
		trace_f = open(trace_fname, 'r')
	except IOError:
		print_error_exit(tag, "trace file {0} does not exist".format(
			trace_fname))
	try:
		os.makedirs(outputdir)
	except OSError:
		# Slightly dangerous, but usually this is a result of me just
		# running my scripts repeatedly while developing them.
		print_unexpected(False, tag, ("outputdir {} already exists - "
			"deleting it and starting from scratch!").format(outputdir))
		shutil.rmtree(outputdir)
		try:
			os.makedirs(outputdir)
		except OSError:
			print_error_exit(tag, ("os.makedirs({}) failed twice; did the "
				"rmtree fail?").format(outputdir))
	output_fname = "{}/analysis-obsolete...".format(outputdir)
	output_f = open(output_fname, 'w')
	
	proc_tracker = processes_tracker()

	return (trace_f, output_f, proc_tracker)

def cleanup(trace_f, output_f):
	tag = "cleanup"

	trace_f.close()
	output_f.close()
	
	return

# Resets all of the plots in PlotList.analysis_plotlist, and sets their
# workingdir and appname using the arguments to this method.
# Returns: nothing.
def setup_multiapp_plots(outputdir, appname):
	tag = 'setup_multiapp_plots'

	print_debug(tag, ("setting all plots in analysis_plotlist to use "
		"basedir {}").format(outputdir))
	for plot in PlotList.analysis_plotlist:
		# The plot objects will be reused across analysis calls, so
		# make sure to reset() them first!
		print_debug(tag, ("before call to set_workingdir, plot has "
			"workingdir={}").format(plot.workingdir))
		plot.reset()
		plot.set_workingdir(outputdir)
		plot.set_currentapp(appname)

	return

def write_perf_data(outputdir, proc_tracker, group_multiproc, target_pids):
	tag = 'write_perf_data'

	proc_groups = create_save_process_groups(outputdir, proc_tracker,
			group_multiproc, target_pids)
	if not proc_groups or len(proc_groups) == 0:
		print_error(tag, ("create_save_process_groups() failed"))
		return
	print_debug(tag, ("PERF: wrote process_groups file to outputdir "
		"{}").format(outputdir))

	return

# Completes all of the plots in the plotlist. The workingdir of each
# plot will be set using the specified basedir before completing
# the plot. Remember, the workingdir will be the basedir plus the
# plotname (which is already set).
def plot_plotlist(plotlist, basedir, appname):
	tag = 'plot_plotlist'

	if not basedir or not appname:
		print_error(tag, ("invalid arg, returning now: basedir={}, "
			"appname={}").format(basedir, appname))
		return

	plotdir = "{}/{}".format(basedir, 'plots')
	try:
		os.makedirs(plotdir)
	except FileExistsError:
		# remove old plots, to avoid confusion.
		print_warning(tag, ("plotdir directory with name {} already "
			"exists! Will delete it and re-create it").format(
			plotdir))
		shutil.rmtree(plotdir)
		os.mkdir(plotdir)

	app_pdffile = plots.new_pdffile(("{}/allplots-{}").format(plotdir,
		appname))

	for p in plotlist:
		p.set_workingdir(plotdir)
		p.add_pdffile(app_pdffile)
		p.complete()
	
	plots.close_pdffile(app_pdffile)

	return

def handle_args(argv):
	tag = 'handle_args'

	parser = analyze_parser
	args = parser.parse_args(argv)
	print_debug(tag, ("parser returned args={}").format(args))
	
	return (args.trace_fname, args.outputdir, args.group_multiproc,
		args.process_userstacks, args.lookup_fns, args.appname,
		args.target_pids, args.skip_page_events)

# May be called from __main__, or may be called by an external script.
def analyze_main(trace_fname, outputdir, group_multiproc,
		process_userstacks, lookup_fns, target_pids, appname,
		skip_page_events):
	tag = 'analyze_main'

	print_debug(tag, ("entered").format())

	# todo?: should we remove and re-create outputdir here? Would
	# ensure that old output in this directory doesn't get mixed
	# up in the new output...

	analysisdir = "{}/{}".format(outputdir, analysisdirname)
	(trace_f, output_f, proc_tracker) = initialize(
		trace_fname, analysisdir)  # opens files

	# Call setup_multiapp_plots() to reset / initialize plots in 
	# PlotList.analysis_plotlist. IMPORTANT: we need to be careful
	# in main here to not actually modify this global list!
	setup_multiapp_plots(analysisdir, appname)
	copy_of_analysis_plotlist = list()
	for plot in PlotList.analysis_plotlist:
		copy_of_analysis_plotlist.append(plot)
	plotlist = copy_of_analysis_plotlist

	process_trace_file(trace_f, proc_tracker, analysisdir, group_multiproc,
		process_userstacks, lookup_fns, target_pids,
		plotlist, appname, skip_page_events)

	output_tracked_processes(output_f, analysisdir, trace_fname,
		proc_tracker, group_multiproc, target_pids)

	newplots = point_in_time_plots(analysisdir, outputdir,
			proc_tracker, group_multiproc, target_pids, appname,
			process_userstacks)
	plotlist += newplots
	print_debug(tag, ("added {} new dynamically-generated plots, now "
		"plotlist has {} plots").format(
		len(newplots), len(plotlist)))

	# Output data that will be used by other scripts:
	#   write_perf_data(): writes out data that will be used for a
	#     subsequent perf analysis, for example the grouped processes.
	#     Because we want the perf analysis to be able to locate it,
	#     put it into perfdatadir, not outputdir!
	#   serialize_plotlist_data(plotlist): will write out the data files for
	#     each series that was added to the plots in the plotlist
	#     during process_trace_file().
	write_perf_data(outputdir, proc_tracker, group_multiproc,
			target_pids)
	
	# Once we have called serialize_plotlist_data, we call plot_plotlist()
	# to generate plots for this one app we've just analyzed. Generating
	# the plots is a "destructive" operation that can only be performed
	# once for the multiapp_plot objects in the plotlist, because the
	# series data will likely be modified to create the plot. However,
	# this is ok for us because the generate_plots script that is
	# usually used to generate plots across *all* apps resets the
	# multiapp_plot objects itself anyway, before reading in the
	# serialized series files.
	serialize_plotlist_data(plotlist)
	plot_plotlist(plotlist, outputdir, appname)
	
	cleanup(trace_f, output_f)     # closes files
	print_debug(tag, ("analysis complete").format())

	# Return the plotlist: any plots that we started with from
	# PlotList.analysis_plotlist, plus any dynamically generated newplots.
	return plotlist

# Main:
if __name__ == '__main__':
	tag = 'main'

	(trace_fname, outputdir, group_multiproc, process_userstacks,
		lookup_fns, appname, target_pids_file,
		skip_page_events) = handle_args(sys.argv[1:])
	print_debug(tag, ("using appname={}").format(appname))

	if not target_pids_file:
		target_pids = []
		print_warning(tag, ("no target_pids file specified, plot "
			"data may not be saved! (see \"do_we_care()\")").format())
	else:
		target_pids = read_target_pids2(target_pids_file)
		print_debug(tag, ("read target_pids {} from {}").format(target_pids,
			target_pids_file))

	analyze_main(trace_fname, outputdir, group_multiproc, process_userstacks,
		lookup_fns, target_pids, appname, skip_page_events)
	print("Analysis complete")

	sys.exit(0)
