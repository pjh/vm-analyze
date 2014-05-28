# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
import trace.vm_common as vm

'''
Tracks information about a PTE that is active in a process' address
space.
'''
class PTE:
	tag = "PTE"

	pfn = None
	flags = None
	pagesize = None
	vma = None

	# Should vma be optional?
	def __init__(self, pfn, flags, pagesize, vma):
		tag = "{0}.__init__".format(self.tag)

		if (not pfn or not flags or not pagesize or
				pagesize < vm.PAGE_SIZE_BYTES or not vma):
			print_error_exit(tag, ("invalid arg: pfn={}, flags={}, "
				"pagesize={}, vma={}").format(pfn, flags, pagesize, vma))

		self.pfn = pfn
		self.flags = flags
		self.pagesize = pagesize
		self.vma = vma

		return

# Searches for a vma that is tracked in the proc_info's vmatable that
# matches the vma-begin-addr from a pte trace event. Handles special
# fork-exec exceptions. The new_pfn argument is unused except for
# debug output.
# This method may return None when there is no vma to link to: either
# because we don't have sufficient information for this process, or
# because the pte event happened during a fork-exec that we're ignoring.
# Currently, there are no other error conditions that cause None to
# be returned.
# Returns: the vma that this pte is linked to, or None if no such
# vma could be found.
def pte_get_linked_vma(proc_info, vma_begin_addr, new_pfn):
	tag = 'pte_get_linked_vma'

	vmatable = proc_info.get_vmatable()
	strict = proc_info.be_strict()
	linked_vma = None
	debughere = False

	try:
		linked_vma = vmatable[vma_begin_addr]
		print_debug2(debughere, tag, ("{}: found vma at {} to link to mapped "
			"pfn {}").format(proc_info.name(), hex_no_X(vma_begin_addr),
			new_pfn))
		if proc_info.use_bprm:
			print_error_exit(tag, ("{}: use_bprm is True, but found a "
				"linked_vma from the vmatable for {}. Should we always "
				"check use_bprm first??").format(proc_info.name(),
				hex_no_X(vma_begin_addr)))

		if linked_vma.is_guard_region():
			print_unexpected(True, tag, ("huh: just-mapped pte linked "
				"to guard-region vma. Does this definitely mean "
				"that the application touched this memory, or just "
				"that a V->P mapping was established (for some "
				"reason...)? vma: {}").format(vma))

	except KeyError:
		# Check for special fork-exec handling: if we are in the middle
		# of an exec (regardless of whether or not a fork *just* took
		# place), then use_bprm may be set to the initial bprm vma. When
		# we get faults that lead to pte_mapped events here during this
		# period when use_bprm is set, we expect the pte_mapped vma to
		# usually (always?) match the bprm vma.
		#   It seems like we could still get faults from other vmas
		#   during a fork-exec while the bprm-vma is set, I think...
		#   but in practice, I haven't encountered this yet.
		# If use_bprm is not set for the process, then we may still be
		# in the middle of a fork (e.g. the dup_mmap events that precede
		# the setting of the bprm-vma); at this time, the process'
		# vmatable may be empty because the process_mmap_trace_event()
		# method is ignoring the initial fork events until the exec
		# is complete. This means that when page faults
		# lead to pte_mapped events here during the fork-exec, we will
		# not find any corresponding vmas in the vmatable (it will be
		# empty, but bprm_vma may be in use). To check for this
		# condition we can look at proc_info.exec_follows_fork, which
		# should be set to True from the first fork event until the
		# first non-special event after the exec is complete.
		#   Note that if a process performs multiple execs, then after
		#   the first fork-exec, the subsequent execs will NOT have
		#   exec_follows_fork set - this is why we check for use_bprm
		#   first. I guess this means that we'll fail down below if we
		#   get a fault for some other non-bprm vma during a second
		#   exec... but I'm not sure this will ever happen.
		# Ok, in office and firefox traces I've seen this sequence of
		# events:
		#     dbus-daemon-5668 2441: mmap_vma_alloc: [__bprm_mm_init]
		#       ffff880044839cf0 @ 7ffffffff000-7ffffffff000 rw-p
		#     dbus-daemon-5668 6292: mmap_vma_resize_unmap: [expand_downwards]
		#     dbus-daemon-5668 7283: mmap_vma_resize_remap: [expand_downwards]
		#     dbus-daemon-5668 0232: pte_mapped: [do_anonymous_page]
		#       ffff880044839cf0 @ 7fffffffe000-7ffffffff000 rw-p
		#       file=[]
		#       faultaddr=00007fffffffefe6 is_major=0
		#       old_pte_pfn=0 old_pte_flags=00000000
		#       new_pte_pfn=64960 new_pte_flags=8000000000000067
		#     dbus-daemon-5668 6283: pte_mapped: [__do_fault]
		#       ffff8800cb14d000 @ 00400000-00406000 r-xp
		#       file=[/usr/bin/dbus-launch]
		#       faultaddr=0000000000404f68 is_major=0
		#       old_pte_pfn=0 old_pte_flags=00000000
		#       new_pte_pfn=1120157 new_pte_flags=00000025
		#     dbus-daemon-5668 0857: mmap_vma_free: [exit_mmap -> remove_vma]
		#     ...
		#   Hmmm: when the pte_mapped - __do_fault event is hit, the fault
		#   address is in the /usr/bin/dbus-launch CODE, and dbus-launch is
		#   the parent process. Ok, I'm not really quite sure what's going
		#   on here (why this page is being accessed in the middle of an
		#   exec system call...), but for the code below, I guess it's ok
		#   to touch vmas other than the bprm-vma...
		if strict:
			if proc_info.use_bprm:
				if vma_begin_addr == proc_info.bprm_vma.start_addr:
					# This actually does happen: mmap_vma_alloc first
					# happens for the bprm-vma, then expand_downwards()
					# unmaps it and remaps it, then it is accessed
					# and is faulted in, with do_anonymous_page()
					# performing the pte mapping. Waaaay cool!
					linked_vma = proc_info.bprm_vma
					print_debug(tag, ("{}: during fork-exec, "
						"mapped a pte to bprm_vma {}").format(
						proc_info.name(), hex_no_X(vma_begin_addr)))
				else:
					# Just use None for the vma - since we're in the
					# middle of an exec and the mmap is being blown
					# away anyway, I'm not concerned about counting
					# this pte event here.
					linked_vma = None
					print_debug(tag, ("{}: during fork-exec, "
						"use_bprm is true, but vma_begin_addr {} "
						"doesn't match bprm_vma {}").format(
						proc_info.name(), hex_no_X(vma_begin_addr),
						hex_no_X(proc_info.bprm_vma.start_addr)))
			elif proc_info.exec_follows_fork:
				linked_vma = None
				print_debug(tag, ("{}: no vma at {} "
					"to link to mapped pfn {}, but exec_follows_fork"
					"={}; vmatable has {} entries").format(
					proc_info.name(), hex_no_X(vma_begin_addr),
					new_pfn, proc_info.exec_follows_fork,
					len(vmatable)))

				if len(vmatable) != 0:
					print_error_exit(tag, ("len(vmatable) is {} during "
						"special exec_follows_fork case - is this "
						"expected??").format(len(vmatable)))
			else:
				# In some traces using "manual" app trace-gathering,
				# I hit this case near the very end of the trace, when:
				#   Top-level python script forked a new python script
				#   to run a command
				#   New python script forked a chown process to change
				#   owner:group of the trace output file
				#   ...
				# What I think happened: the new python process was forked
				# on CPU 001, and the last mmap_vma_* message that I saw
				# from that CPU was in the middle of the dup_mmap of the
				# new python. After the last mmap_vma_*, there were a
				# handful more pte_at messages from core 001 for the
				# parent python, but then no more; however, the child
				# python started running on core 002, so my script tries
				# to deal with its pte_mapped events, but the vma they
				# should be associated with was never copied from the
				# parent due to the trace ending.
				#   What to do about this? Could add a new proc_info flag
				#   that denotes some uncertainty in strictness when we're
				#   near the end of the trace... or, implement the
				#   "optimization" (which I should have done long ago) of
				#   skipping ALL events for processes that are not in
				#   target_pids or are not chlid processes of target_pids.
				# Well, this happened again (on Simon's 6-core system),
				# except that it happened just 43% of the way through
				# the trace, and it happened for a process (redis-server)
				# that we care about - crap. Why do the last events for
				# core 0 come at line 257,141 of a 559,081 line trace??
				#   Is it because core 0's trace buffer actually filled
				#   up? If so, this should be detected in trace_off(),
				#   right? Since it's not being detected, 
				#     
				#   Ugh!! One other thing to try: call "all_cpus" when
				#   tracing is 
				print_error_exit(tag, ("{}: no vma at {} "
					"to link to mapped pfn {}; vmatable has {} "
					"entries, use_bprm={}, exec_follows_fork={}. See "
					"notes above: are we in the middle of a second "
					"exec here that causes a pte fault in some "
					"non-bprm vma? Or, are we near the "
					"end of a multi-core trace that cut off some of "
					"the dup_mmap events for {}, causing its mmap "
					"to be incomplete and causing this method to "
					"fail to find the right vma?").format(
					proc_info.name(), hex_no_X(vma_begin_addr),
					new_pfn, len(vmatable), proc_info.use_bprm,
					proc_info.exec_follows_fork, proc_info.name()))
		
		else:
			# Not strict: we don't care about this event
			linked_vma = None

	return linked_vma


if __name__ == '__main__':
	print_error_exit("not an executable module")

