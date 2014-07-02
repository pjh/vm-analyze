# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Regex documentation:
#   http://docs.python.org/3/howto/regex.html
#   http://docs.python.org/3/library/re.html
#   http://www.regular-expressions.info/reference.html

import re
import sys

mem_type_line = re.compile(r"^(\w+):\s*(\d+) kB$")
hex_range_line = re.compile(
	r"^(?P<begin>[0-9A-Fa-f]+)-(?P<end>[0-9A-Fa-f]+).*")
strace_line_re = re.compile(r"^(?P<pid>[0-9]+)\s+(?P<cmd>\w+)"
	"\((?P<args>.*)\)\s+= (?P<retstr>.+)")
strace_unfinished_re = re.compile(r"^(?P<pid>[0-9]+)\s+(?P<cmd>\w+)"
	"\((?P<args>.*?),?\s+<unfinished ...>")
strace_resumed_re = re.compile(r"^(?P<pid>[0-9]+)\s+<... (?P<cmd>\w+) "
	"resumed> (?P<args>.*)\)\s+= (?P<retstr>.+)")
# Trace events from /sys/kernel/debug/tracing/trace for events enabled in
# /sys/kernel/debug/tracing/events/mmap/mmap_vma:
# Format is:
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION: event-specific...
#           tail-2933  [000] ....   165.472200: mmap_vma: ...
#           bash-3124  [001] d...  1175.107234: sys_write -> 0x2
#           bash-3124  [001] d...  1175.107237: sys_dup2(oldfd: a, newfd: 1)
#           bash-3124  [001] d...  1175.107238: sys_dup2 -> 0x1
#          <...>-3148  [001] ....  1176.632797: mmap_disable_sim: shift_ar...
#    kworker/1:0-23899 [001] d... 1057013505893862: sched_switch: prev_comm=...
#     irqbalance-1455  [001] .... 1057030688020950: mmap_vma_resize_unmap: p...
#           bash-11809 [001] ...1 171543.734505: tracing_mark_write: abracadabra
# Event-specific part looks like (for my "mmap_vma" events):
#   ffff8800c1ab71b0 @ 7f2ee352d000-7f2ee3530000 rw-p 00000000 00:00 0
trace_event_re = re.compile(r"""
	^\s*                            # leading whitespace
	(?P<task>[\w\-<>. \#~/:+]+)-    # some weird characters in task names...
	(?P<pid>\d+)\s+                 # ...
	\[(?P<cpu>\d+)\]\s+             # ...
	(?P<flags>....)\s+              # ...
	(?P<timestamp>[\d.]+):\s+       # should work for both 'local' and TSC
#	(?P<trace_event>\w+)[:( ]\s*    # needed for sys_* call/return...
	(?P<trace_event>\w+):\s+        # ...
	(?P<event_msg>.*)$              # ...
	""", re.VERBOSE)
userstacktrace_begin_re = re.compile(r"""   # not quite a trace_event_re
	^\s*                            # leading whitespace
	(?P<task>[\w\-<>. \#~/:+]+)-    # some weird characters in task names...
	(?P<pid>\d+)\s+                 # ...
	\[(?P<cpu>\d+)\]\s+             # ...
	(?P<flags>....)\s+              # ...
	(?P<timestamp>[\d.]+):\s+       # should work for both 'local' and TSC
	<user[ ]stack[ ]trace>[ ]
	tgid=(?P<tgid>\d+)
	""", re.VERBOSE)
userstacktrace_entry_re = re.compile(r"""
	# [001] =>  <00007f82bd592c37>
	^\s*
	\[(?P<cpu>\d+)\]\s+
	=>\s+
	(<(?P<ip>[\dA-Fa-f]+)>
	 |(?P<ipnotfound>\?\?))    # when ip is 0, " [001] => ??" is printed
	""", re.VERBOSE)   # may have a trailing space after the '>'
userstacktrace_reason_re = re.compile(r"""
	# [001] reason k
	^\s*
	\[(?P<cpu>\d+)\]\s+
	reason\s+
	(?P<reason>\w)
	""", re.VERBOSE)   # may have a trailing space after the '>'
# Get the cpu number from an arbitrary trace event line - assumes
# that there is no other "conflicting" output that consists of
# decimal digits inside of [brackets].
trace_event_cpu_re = re.compile(r"""
	\[(?P<cpu>\d+)\]
	""", re.VERBOSE)
vma_pids_re = re.compile(r"""
	^pid=(?P<pid>\d+)[ ]
	tgid=(?P<tgid>\d+)[ ]
	ptgid=(?P<ptgid>\d+)[ ]
	""", re.VERBOSE)
vma_event_re = re.compile(r"""
	^pid=(?P<pid>\d+)[ ]
	tgid=(?P<tgid>\d+)[ ]
	ptgid=(?P<ptgid>\d+)[ ]
	\[(?P<fn_label>.+)\]:[ ]
	(?P<vma_addr>[0-9A-Fa-f]+)
	[ ]@[ ]
	(?P<rest>.+)$
	""", re.VERBOSE)
maps_line_re = re.compile(r"""
	^(?P<begin_addr>[0-9A-Fa-f]+)-
	(?P<end_addr>[0-9A-Fa-f]+)\s+
	(?P<perms>....)\s+
	(?P<offset>[0-9A-Fa-f]+)\s+
	(?P<dev_major>[0-9A-Fa-f][0-9A-Fa-f]):
	(?P<dev_minor>[0-9A-Fa-f][0-9A-Fa-f])\s+
	(?P<inode>\d+)\s*           # *, not +: may be no trailing whitespace
	(?P<filename>.*)
	""", re.VERBOSE)
MMAP_VMA_EVENT_PREFIX = "mmap_vma_"
  # i.e. for the trace events that I've added, like trace_mmap_vma_alloc()
  # and trace_mmap_vma_free() and trace_mmap_vma_resize_unmap()...:
  # mmap_vma_* is what appears in the FUNCTION part of the trace output.

# Initially, this works for all events in the "pte_event" class in the
# kernel: pte_mapped, pte_update, pte_cow. This regex should be used
# on the 'rest' group of vma_event_re above.
pte_mapped_re = re.compile(r"""
	(?P<begin_addr>[0-9A-Fa-f]+)-
	(?P<end_addr>[0-9A-Fa-f]+)\s+
	(?P<perms>....)\s+
	file=\[(?P<filename>.*)\]\s+         #filename may be empty
	faultaddr=(?P<faultaddr>[0-9A-Fa-f]+)\s+
	is_major=(?P<is_major>\d+)\s+
	old_pte_pfn=(?P<old_pfn>\d+)\s+
	old_pte_flags=(?P<old_flags>[0-9A-Fa-f]+)\s+
	new_pte_pfn=(?P<new_pfn>\d+)\s+
	new_pte_flags=(?P<new_flags>[0-9A-Fa-f]+)
	""", re.VERBOSE)

# pid=18825 tgid=18825 ptgid=18603 [__do_fault]: rss_stat[MM_FILEPAGES]=51
rss_mapped_re = re.compile(r"""
	pid=(?P<pid>\d+)[ ]
	tgid=(?P<tgid>\d+)[ ]
	ptgid=(?P<ptgid>\d+)[ ]
	\[(?P<fn_label>.+)\]:[ ]
	rss_stat\[(?P<pagetype>.+)\]=
	(?P<pagecount>\d+)
	""", re.VERBOSE)

# sched_switch trace events look like this (note: the *_tgid are added by me)
#     <idle>-0     [000] d... 985685743549368: sched_switch:
#     prev_comm=swapper/0 prev_pid=0 prev_tgid=123 prev_prio=120
#     prev_state=R ==> next_comm=validate- hello next_pid=29481
#     next_tgid=123 next_prio=120
#
#     validate-hello-29481 [000] d... 985685743927152: sched_switch:
#     prev_comm=validate-hello prev_pid=29481 prev_tgid=123 prev_prio=120
#     prev_state=x ==> next_comm=kworker/0:1 next_pid=29116 next_tgid=123
#     next_prio=120
#
#     metacity-2734  [001] d... 79587.064714: sched_switch:
#     prev_comm=metacity prev_pid=2734 prev_tgid=2734 prev_prio=120
#     prev_state=S ==> next_comm=gnome-terminal next_pid=2919 next_tgid=2919
#     next_prio=120
sched_switch_event_re = re.compile(r"""
	^\s*
	prev_comm=(?P<prev_comm>[\w\-<>.\#~/: ]+)[ ]
	prev_pid=(?P<prev_pid>\d+)[ ]
	prev_tgid=(?P<prev_tgid>\d+)[ ]
	prev_prio=(?P<prev_prio>\d+)[ ]
	prev_state=(?P<prev_state>[\w|]+)
	[ ]==>[ ]
	next_comm=(?P<next_comm>[\w\-<>.\#~/: ]+)[ ]
	next_pid=(?P<next_pid>\d+)[ ]
	next_tgid=(?P<next_tgid>\d+)[ ]
	next_prio=(?P<next_prio>\d+)
	\s*$""", re.VERBOSE)

tgid_re = re.compile(r"\stgid=(?P<tgid>\d+)\s")  # use search(), not match()!
hexnum_re = re.compile(r"^0x(?P<hexnum>[0-9A-Fa-f]+)")
posint_re = re.compile(r"^(?P<posint>[0-9]+)$")
retstr_err_re = re.compile(r"^(?P<errnum>-[0-9]+) (?P<errname>E[A-Z]+) "
	"\((?P<descr>.*)\)")
sigchld_line_re = re.compile(r"^--- SIGCHLD .+---$")
sigprof_line_re = re.compile(r"^--- SIGPROF .+---$")
sig_line_re = re.compile(r"^--- SIG.+---$")
execve_args_re = re.compile(r"\"(?P<fullcmd>.+)\", \[\"(?P<arg1>.+?)\""
	"(?P<argsleft>.*)\], \[.+\]")
	# '?' needed for arg1 matching to be non-greedy
mmap_args_re = re.compile(r"^(?P<addr>.+), (?P<length>.+), (?P<prot>.+), "
    "(?P<flags>.+), (?P<fd>.+), (?P<offset>.+)")   # that was easy
mprotect_args_re = re.compile(r"^(?P<addr>.+), (?P<length>.+), (?P<prot>.+)")
munmap_args_re = re.compile(r"^(?P<addr>.+), (?P<length>.+)")

'''
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
  00657000-00658000 r--p 00057000 08:01 9968332  /usr/bin/screen
  ...
  00658000-0065c000 rw-p 00058000 08:01 9968332  /usr/bin/screen
  0065c000-00669000 rw-p 00000000 00:00 0
  00a86000-00aa7000 rw-p 00000000 00:00 0        [heap]
  7f30dc28f000-7f30dc29b000 r-xp 00000000 08:01 10224318  /lib/x86_64-li...
  7f30dc8c0000-7f30dc8c2000 rw-p 00000000 00:00 0
  7fff76ca4000-7fff76cc5000 rw-p 00000000 00:00 0  [stack]
  7fff76dff000-7fff76e00000 r-xp 00000000 00:00 0  [vdso]
  ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0  [vsyscall]
The fields in these header lines are:
  address-address permissions offset device inode pathname
    address-address: virtual address location
    permissions: s = shared, p = private (copy on write)
    offset: offset into the file / whatever (hex!)
    device: major:minor number
    inode: inode on the device, or 0 for no inode
So, we can use a regular expression for the hex-hex address range to
match the header lines.
'''
header_line = re.compile(
  r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)\s+(....)\s+([0-9A-Fa-f]+)\s+"
   "(\d\d:\d\d)\s+(\d+)\s+(.*)")
    # note: the last group in this regex may be empty ('') - no name)!
heap_line = re.compile(r".*\[heap\].*")
anon_hp_line = re.compile(r"^AnonHugePages:\s+(\d+) kB$")
HEADER_LINE = re.compile(
	r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)\s+(....)\s+([0-9A-Fa-f]+)\s+"
	 "([0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f])\s+(\d+)\s+(.*)")
		# Regular expression to match a header line in a maps/smaps file;
		# the groups are (remenber these are all strings):
		#   (begin_address, end_address, permissions, offset-in-file,
		#    device, inode, filename)
		# The filename may be empty ('') for an anonymous mapping.

# Output of "ps -eHo pid,pgid,args", when called from this
# capture_strace.py script, usually looks like this:
#   6495  6495     /bin/bash
#  30890 30890       python3 ./capture_strace.py sleep 3
#  30891 30890         strace -o strace-captures/sleep/strace sleep 3
#  30892 30890           sleep 3
#  30893 30890         /bin/sh -c ps -eHo pid,pgid,args
#  30894 30890           ps -eHo pid,pgid,args
# When the -e flag is left out, this is the ONLY output (along with
# the first-line header).
#
# However, when the process being straced is very short-lived, or
# the last time this method is called on an straced process, the
# output may look like this:
#  32629 32629   python3 ./capture_strace.py echo abracadabra
#  32630 32629     [strace] <defunct>
#  32632 32629     /bin/sh -c ps -Ho pid,pgid,args
# In this case, we'll return an empty list of child pids.
ps_line = re.compile(
	r"^\s*(?P<pid>[0-9]+)\s+(?P<pgid>[0-9]+)(?P<spaces> +)(?P<cmd>\S+.*)$")
valid_pid_dir = re.compile(r"^(\d+?)$")  # just one or more digits
valid_pid_file = valid_pid_dir

# regular expressions for matching libraries that we care about:
#lib_ld_re = re.compile(r"ld-[\d.]+\.so")
lib_ld_re = re.compile(r"ld-2\.[\d]+\.so")   # 2.something
libc_re   = re.compile(r"libc-2\.[\d]+\.so")   # 2.something
libdl_re  = re.compile(r"libdl-2\.[\d]+\.so")   # 2.something

# Pin regular expressions: probably not a good idea to use groups() to get
# values from them - many values are optional, and there are internal
# unnamed groups, and so on. 
# From my Pintool: memory trace events currently look like this:
#         Write:  0x7fffcdd47148
#		   Read:  0x7f7dead9cb80
pin_mem_event_re = re.compile(r"""
	^\s+
	(?P<pid>\d+)-
	(?P<op>Write|Read):\s+
	0x(?P<addr>[0-9A-Fa-f]+)
	""", re.VERBOSE) 
	# (pid, op, addr) = m.groups()
# Call trace call events currently look like this:
#   1057031723322621 Call 0x00007f7deab7f300 /lib64/ld-linux-x86-64.so.2:.text+0x000000004810 -> 0x00007f7deab853a0 /lib64/ld-linux-x86-64.so.2:_dl_rtld_di_serinfo+0x000000002480(0x7f7dead9d9d8, 0x606250cd, ...)
#   1057033733315607 | | | Call 0x00000000004007c7 /home/pjh/research/virtual/pin/validate-hello:procedure+0x000000000029 -> 0x00000000004005e0 /home/pjh/research/virtual/pin/validate-hello:.plt+0x000000000020(0x4009eb,               0x7fffcdd4807f, ...)
#   1057043161676241 | | | Tailcall 0x00007f7dd751fb7f /lib/x86_64-linux-gnu/libc.so.6:_IO_adjust_column+0x0000000004cf -> 0x00007f7dd7520406 /lib/x86_64-linux-gnu/libc.so.6:_IO_list_resetlock+0x0000000001b6(0x7f7dd7401000, 0x7f7dd785c2e3, ...)
pin_call_event_re = re.compile(r"""
	^\s*
	(?P<tsc>\d+)\s+
	(?P<depth>(\|\s)*)                   # (\|\s) works, (\| ) doesn't.
	(?P<pid>\d+)-
	(?P<op>Call|Tailcall)\s
	0x(?P<call_insn_addr>[0-9A-Fa-f]+)\s+
	((?P<caller_module>[\w\-/.+]+):
	 (?P<caller_fn>[\w\-.]+))?\s?              # optional...
	(\+0x(?P<caller_offset>[0-9A-Fa-f]+)\s+)?  # optional...
	->\s+
	0x(?P<callee_addr>[0-9A-Fa-f]+)
	(\s+(?P<callee_module>[\w\-/.+]+):       # apparently this is opt-
	 (?P<callee_fn>[\w\-.]+))?               # ional as well...
	(\+0x(?P<callee_offset>[0-9A-Fa-f]+))?   # ?: this is optional
	\((?P<callee_args>[\w, .]*)\)
	""", re.VERBOSE)
# Call trace return events currently look like this:
#  1057031727299631 Return 0x00007f7deab8540a /lib64/ld-linux-x86-64.so.2:_dl_rtld_di_serinfo+0x0000000024ea returns: 0x7f7deab7a314
#  1057043161983582 | | | Return 0x00007f7dd751fa88 /lib/x86_64-linux-gnu/libc.so.6:_IO_adjust_column+0x0000000003d8 returns: 0
pin_return_event_re = re.compile(r"""
	^\s*
	(?P<tsc>\d+)\s+
	(?P<underflow>return[ ]underflow\s+)?    # optional
	(?P<depth>(\|\s)*)                       # (\|\s) works, (\| ) doesn't.
	(?P<pid>\d+)-
	(?P<op>Return)\s
	0x(?P<return_insn_addr>[0-9A-Fa-f]+)
	(\s+(?P<return_module>[\w\-/.+]+):       # optional too...
	 (?P<return_fn>[\w\-.]+))?               # optional too...
	(\+0x(?P<return_offset>[0-9A-Fa-f]+))?   # ?: optional
	\s+returns:\s+
	(?P<return_val>.*)$
	""", re.VERBOSE)
#pin_return_event_re = re.compile(r"""^\s*(?P<tsc>\d+)\s+(?P<underflow>@@@ return underflow\s+)?(?P<depth>(\|\s)*)(?P<pid>\d+)-(?P<op>Return)[ ]0x(?P<return_insn_addr>[0-9A-Fa-f]+)(\s+(?P<return_module>[\w\-/.]+):(?P<return_fn>[\w\-.]+))?(\+0x(?P<return_offset>[0-9A-Fa-f]+))?\s+returns:\s+(?P<return_val>.*)$""", re.VERBOSE)
# SIG signal=0xf on thread 0 at address 0x7f47343db830 FATALSIG15
pin_signal_event_re = re.compile(r"""
	^\s*
	SIG[ ]
	signal=0x(?P<signum>[0-9A-Fa-f]+)[ ]
	on[ ]thread[ ](?P<threadnum>\d+)[ ]
	at[ ]address[ ]0x(?P<addr>[0-9A-Fa-f]+)[ ]
	(?P<descr>.*)
	""", re.VERBOSE)

if __name__ == '__main__':
	print('This file cannot be run stand-alone')
	sys.exit(1)
