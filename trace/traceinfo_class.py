# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
import conf.system_conf as sysconf
import datetime
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time

# Linux "perf" tool:
# On verbena, there are just two "generic" hw performance counters, so
# when more than two events are selected here, the events are multiplexed
# over the counters during the "perf record" run. So, for example, if
# four events are active here, they will each only be counted for about
# 50% of the record's execution.
# To see the full list of available events, run "perf list".
#PERF_TRACE_DEFAULT_ON = False
PERF_TRACE_DEFAULT_ON = True
  # can be overridden by individual trace_on() callers.
PERF_EVENTS = [
	'dTLB-loads',
	'dTLB-load-misses',
	'dTLB-stores',
	'dTLB-store-misses',
	#'dTLB-prefetches',
	#'dTLB-prefetch-misses',
#	'iTLB-loads',
#	'iTLB-load-misses',
	#'L1-dcache-loads',
	#'L1-dcache-load-misses',
	#'L1-dcache-stores',
	#'L1-dcache-store-misses',
	#'L1-dcache-prefetches',
	#'L1-dcache-prefetch-misses',
	#'L1-icache-loads',
	#'L1-icache-load-misses',
	#'L1-icache-prefetches',
	#'L1-icache-prefetch-misses',
	#'LLC-loads',
	#'LLC-load-misses',
	#'LLC-stores',
	#'LLC-store-misses',
	#'LLC-prefetches',
	#'LLC-prefetch-misses',
	]
PERF_FREQ = 1000
  # By using the -F flag to perf record, the number of events counted
  # before generating a sample interrupt will be dynamically tuned to
  # sample approximately F times every second (so higher PERF_FREQ == 
  # more samples with smaller periods). For example, set to 1000
  # to get 1000 samples/s, or about 1 sample every millisecond. (going
  # lower than 1 ms is probably a poor idea).
  #   I verified that this is right - for a small graph500 run, -F 100
  #   captures 1473 dTLB-load samples, whereas -F 1000 captures about
  #   10x as many, 14575 samples.
  # I examined the plot output for Graph500, and using -F 1000 results
  # in a less-jagged plot than using -F 100, with no other apparent
  # side effects other than 10x more samples. The general calculated
  # miss rates look pretty much the same, so a less-jagged plot seems
  # to indicate a more-accurate plot. I guess I'll stick with -F 1000
  # for now, unless it seems to cause sample periods to become too
  # small, which could potentially be problematic...
PERF_CMD  = "{}/perf".format(sysconf.PERF_DIR)
PERF_EVENTS_STR = ','.join(PERF_EVENTS)
PERF_RECORD_OPTS = "record -vvv -a -i -F {} -e {}".format(
		PERF_FREQ, PERF_EVENTS_STR)
  # Use -a and don't specify a particular command: perf record will
  #   just run until it gets ctrl-c (SIGINT).
  # -i: child tasks don't inherit counters. I'm not sure if this applies
  #   to hw events anyway, but do it to be sure; I should be able to account
  #   for parent/child stuff in my own scripts.
PERF_STDOUT     = 'perf.stdout'
PERF_STDERR     = 'perf.stderr'
PERF_DATA       = 'perf.data'
PERF_DUMPFILE   = 'perf.dump'
PERF_REPORTFILE = 'perf.report'

# Tracing directories and parameters: 1 for true / enable, 0 for false /
# disable.
# Comments:
#   - With sched_switch tracing enabled, the trace buffer will fill up
#     very quickly - even with 678 MB of buffer per-CPU, I couldn't
#     complete a full Cassandra start+load+run.
#   - Does enabling userstack_syms also make the trace buffer fill
#     up more quickly, or not?
#   - clock: use 'local' for a nanosecond-granularity clock, which should
#     approximately sync up with events in a 'perf record' trace. Never
#     use 'global' or your system will become unresponsive! 'x86-tsc'
#     works, but doesn't seem to be too helpful at the moment.
tracing_dir = "{}/tracing".format(sysconf.sys_debug_dir)
#trace_buf_mb_per_core = 512       # per-CPU!
trace_buf_mb_per_core = int(sysconf.suggested_tracebuf_size_kb / 1024)
trace_clock          = 'local'
trace_userstacks     = 0
trace_userstack_syms = 0
  # tracing/options/sym-userobj: attempt to look up stack fns. Note
  # that this flag may not work if other tracing/options/ fields (besides
  # userstacktrace) are enabled.
trace_vma_events     = 1
trace_pte_events     = 0
trace_rss_events     = 0
trace_sched_switch   = 0
  # Note: depending on how kernel is built, may cause deadlock during
  # userstacktrace collection??
trace_sched_fork     = 0
trace_sys_mprotect   = 0
all_cpus_prog = "{}/test-programs/all_cpus".format(sysconf.apps_dir)

tracefilename   = 'trace-events-full'

'''
  ...
'''
class traceinfo:
	tag = 'traceinfo'

	# Members:
	appname = None
	tracing_on = None
	trace_outputdir = None
	trace_on_perf_too = None   # was perf turned on via trace_on()?
	perf_outputdir = None
	perf_tracing_on = None    # is perf trace process active?
	perf_p = None             # Popen object for perf process
	perf_stdout = None
	perf_stderr = None
	pdata_fname = None
	trace_on_time = None
	perf_on_time = None

	def __init__(self, appname):
		tag = "{}.__init__".format(self.tag)

		if not appname:
			print_error_exit(tag, ("missing argument: appname={}").format(
				appname))
		self.appname = appname
		self.tracing_on = False
		self.trace_outputdir = None
		self.perf_outputdir = None
		self.perf_tracing_on = False
		self.trace_on_perf_too = False
		self.perf_p = None
		self.perf_stdout = None
		self.perf_stderr = None
		self.pdata_fname = None
		self.trace_on_time = None
		self.perf_on_time = None

		return

	# This method performs the following steps:
	#   - Set the kernel tracing options and save them in the outputdir
	#   - Turn on kernel tracing
	#   - Run a small program to ensure that all CPU tracing buffers are active
	# Returns: True on success, False on error.
	def trace_on(self, outputdir, descr, use_perf=PERF_TRACE_DEFAULT_ON,
			targetpid=None):
		tag = "{}.trace_on".format(self.tag)

		if self.tracing_on:
			print_error(tag, ("tracing is already activated!"))
			return False

		success = True
		tdir = tracing_dir

		if not os.path.exists(outputdir):
			os.makedirs(outputdir)

		if (trace_userstacks != 0 and 
            (trace_pte_events != 0 or trace_rss_events != 0)):
			print_error_exit(tag, ("can't set both trace_userstacks={} "
				"and trace_pte_events={} or trace_rss_events={} - "
                "otherwise, when collecting "
				"userstack entries for 'do_page_fault' code path that "
				"contains pte trace events, you may invoke further "
				"page faults, causing recursive trace events or "
				"whatever and leading to deadlock!").format(
				trace_userstacks, trace_pte_events, trace_rss_events))

		# Set kernel tracing options:
		options = []
		options.append(("echo 0 > {}/tracing_on").format(tdir))
		options.append(("echo {} > {}/buffer_size_kb").format(
			int(trace_buf_mb_per_core*1024), tdir))
		options.append(("echo {} > {}/trace_clock").format(trace_clock, tdir))
		options.append(("echo 0 > {}/options/overwrite").format(tdir))
		options.append(("echo {} > {}/options/sym-userobj").format(
			trace_userstack_syms, tdir))
		options.append(("echo {} > {}/options/userstacktrace").format(
			trace_userstacks, tdir))
		options.append(("echo {} > {}/events/mmap/enable").format(
			trace_vma_events, tdir))
		options.append(("echo {} > {}/events/pte/enable").format(
			trace_pte_events, tdir))
		options.append(("echo {} > {}/events/rss/enable").format(
			trace_rss_events, tdir))
		options.append(("echo {} > {}/events/sched/sched_switch/"
			"enable").format(trace_sched_switch, tdir))
		options.append(
			("echo {} > {}/events/sched/sched_process_fork/enable").format(
			trace_sched_fork, tdir))
		options.append(
			("echo {} > {}/events/syscalls/sys_enter_mprotect/enable").format(
			trace_sys_mprotect, tdir))
		options.append(
			("echo {} > {}/events/syscalls/sys_exit_mprotect/enable").format(
			trace_sys_mprotect, tdir))
		options.append(("echo > {}/trace").format(tdir))  # reset trace
		write_conf_file(options, "{}/kernel-trace-options".format(outputdir),
				overwrite=True)
			# If we use the same traceinfo for multiple trace-on trace-off
			# cycles and the outputdir is the same (e.g. for a manualapp...),
			# just overwrite this file.

		# Prepend sudo to every command: kernel tracing requires root. To
		# allow redirection to work, must start a full root shell and pass
		# the command to it?
		#   No - turns out that for these sudo commands, shell=True is
		#   NOT needed, even when the command redirects its stdout/stderr
		#   to a file, as long as the args are split using shlex. shlex
		#   puts the entire 'command' into one arg which is passed to
		#   the new root shell, so the redirection is encapsulated in
		#   that argument.
		#   I think that shell=True IS required when executing a non-
		#   sudo command that uses redirection directly; of course, in
		#   this case an alternative is to set the stdout= and stderr=
		#   arguments instead.
		for option in options:
			cmdline = "sudo bash -c '{}'".format(option)
			args = shlex.split(cmdline)
			retcode = subprocess.call(args)
			if retcode != 0:
				print_error(tag, ("command \"{}\" returned non-zero code "
					"{}").format(cmdline, retcode))
				return False

		self.trace_on_time = time.perf_counter()
		  # Requires Python 3.3!
		  # http://docs.python.org/3/library/time.html#time.perf_counter

		# Ok, activate the kernel trace:
		cmdline = "sudo bash -c 'echo 1 > {}/tracing_on'".format(tdir)
		args = shlex.split(cmdline)
		print_debug(tag, "args={}".format(args))
		retcode = subprocess.call(args)
		if retcode != 0:
			print_error(tag, ("command \"{}\" returned non-zero code "
				"{}").format(cmdline, retcode))
			return False
		
		self.tracing_on = True

		# all_cpus is a program used to spawn a thread on every CPU in the
		# system, so that the kernel tracing subsystem kicks in - otherwise,
		# you may see "CPU 1 buffer started" messages in the trace output
		# after trace events that you want to see have already passed! I have
		# yet to find a better way to accomplish this...
		null = get_dev_null()
		print_debug(tag, ("calling all_cpus: {}").format(all_cpus_prog))
		args = shlex.split(all_cpus_prog)
		retcode = subprocess.call(args, stdout=null, stderr=null)
		if retcode != 0:
			print_error(tag, ("command {} returned non-zero code "
				"{}").format(all_cpus_prog))
			success = False
		null.close()

		self.trace_outputdir = outputdir

		# Turn on hardware event sampling using perf? If so, use the same
		# outputdir as for kernel trace:
		if use_perf:
			self.trace_on_perf_too = True
			perfsuccess = self.perf_on(self.trace_outputdir)
			success = success and perfsuccess

		if targetpid:
			# Ignore errors (e.g. if process has already died, then
			# copy will fail...)
			copy_proc_file(targetpid, 'maps', ("{}/maps.{}").format(
				self.trace_outputdir, 'trace_on'))
			copy_proc_file(targetpid, 'smaps', ("{}/smaps.{}").format(
				self.trace_outputdir, 'trace_on'))

		return success

	# This method takes a trace checkpoint, which just consists of:
	#   - Echoing a string to the kernel trace_marker
	#   - Saving the current process tree to a file in the outputdir
	#     that was passed to trace_on().
	# For best results, the description argument should be short and free
	# of unusual characters - it will eventually end up as a filename
	# prefix when the analysis scripts are run.
	# Returns: 'success' on normal operation, 'full' if trace checkpoint
	#   failed because trace buffer filled up, 'error' if some other
	#   error occurred.
	def trace_checkpoint(self, descr, targetpid=None):
		tag = "{}.trace_checkpoint".format(self.tag)

		if not self.tracing_on:
			print_error(tag, "tracing is not activated!")
			return False

		retval = 'success'
		if not descr or len(descr) == 0:
			print_error_exit(tag, ("descr is None or empty string").format())
	
		# Warning: executing subprocess with shell=True is a potential
		# security vulnerability: make sure that this is not exposed to
		# external users!
		cmdline = "sudo bash -c 'echo {} > {}/trace_marker'".format(descr,
			tracing_dir)
		args = shlex.split(cmdline)
		retcode = subprocess.call(args)
		if retcode == 1:
			# Note: after having this error happen (about halfway through
			# a "null" kernel build), I examined the trace-events-full file
			# and found that it is likely due to the trace buffer filling up
			# on ONE cpu core. The final trace event that I found for cpu
			# 0 was a resize-unmap (not followed by a resize-remap); however,
			# for several thousand lines after this, there were still trace
			# events for cpu 1, including two more checkpoints taken
			# successfully!
			#   With a buffer_size_kb of 694272 (678 MB PER CORE), the text
			#   version of the trace file only took up 292 MB! So the in-memory
			#   representation of trace events, with userstacktrace enabled,
			#   appears to be larger than the textual representation...
			# Also note: the trace buffer fills up significantly slower when
			# userstacks are not captured (even when sched_fork events are
			# captured instead); my kernelbuild trace ran nearly all the way
			# to completion (260 seconds), rather than the buffer filling
			# up after ~120 seconds with userstacks.
			print_error(tag, ("checkpoint command {} returned 1: most "
				"likely the trace buffer is full!").format(cmdline))
			retval = 'full'
		elif retcode != 0:
			print_error(tag, ("command \"{}\" returned non-zero code "
				"{}").format(cmdline, retcode))
			retval = 'error'
		else:
			print_debug(tag, ("trace checkpoint: {}").format(descr))

		# Save the current process tree:
		sanitized = sanitize_fname(descr, False)
		pstree_fname = "{}/pstree.{}".format(
			self.trace_outputdir, sanitized)
		save_pstree(pstree_fname)

		if targetpid:
			# Ignore errors (e.g. if process has already died, then
			# copy will fail...)
			copy_proc_file(targetpid, 'maps', ("{}/maps.{}").format(
				self.trace_outputdir, sanitized))
			copy_proc_file(targetpid, 'smaps', ("{}/smaps.{}").format(
				self.trace_outputdir, sanitized))

		return retval

	# Waits for a process being traced to complete. The process arg should
	# come from a call to subprocess.Popen(). If the poll argument is set to
	# 0 or None, then this method will simply wait indefinitely for the
	# process to end using wait(), and no trace checkpoints will be taken at
	# any time during this method. If the poll argument is nonzero, then
	# this method will sleep for that many seconds, take a checkpoint
	# (named using the cp_prefix), then check if the process is still running;
	# if it is, it will sleep again and repeat.
	#   Note: Python 3.3 adds support for *timeouts*, which could/should be
	#   added to this method when the Python installation is upgraded... TODO
	# If targetpid is None, then the process.pid will be used for copying
	# /proc files when periodic checkpoints are taken. If targetpid is
	# set, then this pid will be used instead of process.pid (i.e.
	# process.pid may be a *client*, so targetpid should be set to
	# the *server's* pid.
	# 
	# Returns: 'success' in the normal case, 'full' if the trace buffer
	#   filled up while waiting, 'error' on error.
	def trace_wait(self, process, poll, cp_prefix, targetpid=None):
		tag = "{}.trace_wait".format(self.tag)

		if not self.tracing_on:
			print_error(tag, "tracing is not active!")
			return 'error'

		retval = 'success'
		if targetpid is None:
			targetpid = process.pid

		if not poll:
			# Don't do anything with checkpoints, before after or during!
			print_debug(tag, ("waiting indefinitely for process {} to "
				"complete").format(process.pid))
			process.wait()
		else:
			print_debug(tag, ("starting polling loop on process {} with "
				"period {} seconds").format(process.pid, poll))
			done = None
			elapsed = 0
			while done is None:
				cp_name = "{}-poll{}".format(cp_prefix,
						"{}".format(elapsed).zfill(4))
				retcode = self.trace_checkpoint(cp_name, targetpid)
				if retcode == 'full':
					retval = retcode
					print_warning(tag, ("trace buffer filled up, will "
						"stop polling and just wait for process to "
						"complete, and will return {}").format(retval))
					process.wait()
					poll = 0
				elif retcode == 'error':
					retval = 'error'
					print_error(tag, ("trace_checkpoint failed, will "
						"stop polling and just wait for process to "
						"complete, and will return {}").format(retval))
					process.wait()
					poll = 0
				time.sleep(poll)
				process.poll()
				done = process.returncode
				elapsed += poll

		print_debug(tag, ("process {} completed with returncode "
			"{}, returning {}").format(process.pid,
			process.returncode, retval))
		return retval

	# This method performs the following steps:
	#   - Disables kernel tracing
	#   - Copies the trace events output to a file in the output directory
	#   - "Trims" the trace events file if the trace buffer filled up during
	#     the trace, so that the last event in the trace file is the last
	#     line for the particular CPU whose buffer filled up first.
	# Returns a tuple: (success, buffer-full). If buffer-full is True,
	#   it means that the trace file was trimmed before returning.
	def trace_off(self, descr, targetpid=None):
		tag = "{}.trace_off".format(self.tag)

		# If we started perf at the end of trace_on, then stop perf at
		# the beginning of trace_off.
		if self.trace_on_perf_too:
			self.perf_off()
			self.trace_on_perf_too = False

		if not self.tracing_on:
			print_error(tag, "tracing not active!")
			return False

		success = True
		if not descr or len(descr) == 0:
			print_error_exit(tag, ("descr is None or empty string").format())

		'''
		# See comments in pte_get_linked_vma(): in certain traces, it
		# appears that the trace stops early on one CPU core (sometimes
		# REALLY early), which is problematic e.g. when that core is
		# in the middle of emitting mmap_vma_dup_mmap events. For some
		# reason though, when we take a checkpoint for trace-off below,
		# it doesn't return an error for these traces, so we don't
		# recognize that the trace buffer filled (apparently) for some
		# core. SO, try calling all_cpus here (all_cpus is described
		# in trace_on()) in an attempt to either "flush" the "stalled"
		# core's trace messages to the log, or force the trace-off
		# to return buffer-full for the stalled/full cpu.
		#
		# Is it possible that the trace buffer for whatever core in
		# those traces wasn't actually full, but rather that the core
		# was somehow "stalled" on some other operation, and its events
		# never made it into the log? Perhaps, but from what (little) I
		# know about the kernel tracing infrastructure, I don't see
		# why this would be likely...
		#
		# Is it possible that the trace-off checkpoint only returns
		# 'full' when the tracing_mark_write happens to go to the
		# CPU core whose buffer is actually full? This seems more
		# likely... why didn't I notice this before??
		null = get_dev_null()
		print_debug(tag, ("calling all_cpus: {}").format(all_cpus_prog))
		args = shlex.split(all_cpus_prog)
		retcode = subprocess.call(args, stdout=null, stderr=null)
		if retcode != 0:
			print_error(tag, ("command {} returned non-zero code "
				"{}").format(all_cpus_prog))
			success = False
		null.close()
		'''

		# Take a checkpoint before disabling trace - I think this is helpful
		# most of the time, and it also tells us if the trace buffer filled
		# up during the trace or not. If the buffer did fill up, we will
		# trim the trace file, but we won't do anything else differently
		# in this method. Ignore 'error' retcode on final trace_checkpoint.
		retcode = self.trace_checkpoint('trace-off', targetpid)
		if retcode == 'full':
			buffer_full = True
		else:
			buffer_full = False

		# TODO: I'm not sure how reliable the method of detecting trace-
		# buffer-full by receiving a write error on a trace_mark
		# checkpoint write is; when I moved from my dual-core machine
		# to a six-core machine, two out of my first three traces appear
		# to have filled up the trace buffer on one core, but the
		# trace-off checkpoint didn't detect it, leading to errors
		# during my analysis. Looking at the trace-events file more
		# closely, it looks like actually the trace-off checkpoint
		# goes to just a single core, so I'm guessing that the trace
		# buffer is only detected as full when that trace-off marker
		# happens to go to the core whose buffer is full (duh). I guess
		# I didn't notice this earlier because the chance was 50%
		# when running on my dual-core machine...
		#   I finally did see a similar error for a trace from verbena:
		#   for chrome, I got an error about unmapping a vma that doesn't
		#   exist, and the error arose from the line in the trace-events
		#   file immediately after the last line for cpu 001, implying
		#   that more vma events happened on cpu 1 but they didn't fit
		#   in the trace buffer. Two tracing_mark_writes occurred in
		#   the the trace-events file after this line (both on cpu 000,
		#   of course).
		#
		# Anyway, a more reliable way to detect when the trace buffer
		# is full is probably to examine the "per_cpu/cpu1/stats" files
		# under the kernel's tracing directory. These files have two
		# fields, "overrun" and "dropped events", that should indicate
		# that the trace buffer filled up, so examining them on every
		# core should be sufficient to detect a full trace buffer.
		# I'm not exactly sure which of these fields makes more sense;
		# do some experiments to figure out which field to use (or
		# just use both), then add a method that checks these files
		# for every CPU and calls trim_trace_file() if necessary.
		# Actually, these files should be checked on every checkpoint
		# too, not just when the trace is turned off - this will enable
		# us to exit our application run early if we detect a full
		# buffer at a checkpoint.
		#
		# EVEN BETTER: use trace_pipe while the trace is executing
		# to read trace events and write them to a file, avoiding
		# trace buffer overflows altogether!? See:
		# https://www.kernel.org/doc/Documentation/trace/ftrace.txt

		# Disable kernel tracing:
		# Warning: executing subprocess with shell=True is a potential
		# security vulnerability: make sure that this is not exposed to
		# external users!
		cmdline = "sudo bash -c 'echo 0 > {}/tracing_on'".format(
			tracing_dir)
		args = shlex.split(cmdline)
		retcode = subprocess.call(args)
		if retcode != 0:
			print_error(tag, ("command \"{}\" returned non-zero code "
				"{}").format(cmdline, retcode))
			success = False
		
		self.tracing_on = False

		# elapsedtime should be a float representing the *seconds* elapsed.
		elapsedtime = time.perf_counter() - self.trace_on_time
		lines = ["{}".format(elapsedtime)]
		write_conf_file(lines,
				"{}/trace.elapsedtime".format(self.trace_outputdir),
				overwrite=True)
		self.trace_on_time = None

		# Copy the kernel trace events file to the output directory. It would
		# be better to perform this using python open - read - write etc.
		# commands, but because we need sudo to read the trace file, just
		# execute a shell command:
		#   todo: append a numeric suffix to the trace file name?
		dest = "{}/{}".format(self.trace_outputdir, tracefilename)
		if os.path.exists(dest):
			timestamp = datetime.datetime.now().strftime("%H.%M.%S")
			print_debug(tag, ("trace file already exists at {}, so "
				"appending timestamp {} for subsequent trace file").format(
				dest, timestamp))
			dest = "{}.{}".format(dest, timestamp)

		print_debug(tag, ("copying trace events file to {}").format(dest))
		cmdline = "sudo bash -c 'cat {}/trace > {}; chown {}:{} {}'".format(
			tracing_dir, dest, sysconf.trace_user,
			sysconf.trace_group, dest)
		args = shlex.split(cmdline)
		retcode = subprocess.call(args)
		if retcode != 0:
			print_error(tag, ("command \"{}\" returned non-zero code "
				"{}").format(cmdline, retcode))
			success = False

		if buffer_full:
			print_debug(tag, ("trace buffer filled up, so calling "
				"trim_trace_file()").format())
			trim_trace_file(dest)

		self.trace_outputdir = None

		return (success, buffer_full)

	# Returns True if perf tracing was successfully activated, False on
	# error.
	def perf_on(self, outputdir):
		tag = "{}.perf_on".format(self.tag)

		if self.perf_tracing_on:
			print_error(tag, ("perf tracing is already on! pid={}").format(
				self.perf_p.pid))
			return False

		if not os.path.exists(outputdir):
			os.makedirs(outputdir)
		self.perf_outputdir = outputdir
		pout = "{}/{}".format(self.perf_outputdir, PERF_STDOUT)
		perr = "{}/{}".format(self.perf_outputdir, PERF_STDERR)
		self.perf_stdout = open(pout, 'w')
		self.perf_stderr = open(perr, 'w')
		self.pdata_fname = "{}/{}".format(self.perf_outputdir, PERF_DATA)

		self.perf_on_time = time.perf_counter()

		# perf generally works best when run as root - when not root,
		# some /proc files need to be set correctly to enable users to
		# have full access to the counters and whatnot, and other
		# things also tend to fail in unexpected / undocumented ways.
		cmdline = "sudo bash -c '{} {} -o {}'".format(PERF_CMD,
				PERF_RECORD_OPTS, self.pdata_fname)
		print_debug(tag, ("perf cmdline: {}").format(cmdline))
		args = shlex.split(cmdline)
		perf_p = subprocess.Popen(args, stdout=self.perf_stdout,
				stderr=self.perf_stderr)
		if not perf_p:
			print_error(tag, ("command \"{}\" returned None").format(
				cmdline))
			return False

		self.perf_p = perf_p
		self.perf_tracing_on = True
		print_debug(tag, ("successfully started background perf "
			"record process, pid={}").format(self.perf_p.pid))

		return True

	# Returns: nothing.
	def perf_off(self):
		tag = "{}.perf_off".format(self.tag)

		if not self.perf_tracing_on or not self.perf_p:
			print_error(tag, ("perf tracing is not on! perf_tracing_on="
				"{}, perf_p={}").format(self.perf_tracing_on, self.perf_p))
			return

		# To stop the perf event tracing, we simply need to kill the
		# 'perf record' process. SIGINT (Ctrl-C) works.
		# However, we need to run this as root - ugh. Just use another
		# sudo bash -c command... (have to do this for Cassandra too).
		print_debug(tag, ("sending SIGINT to perf_p process {}").format(
			self.perf_p.pid))
		cmdline = ("sudo bash -c 'kill -SIGINT {}'").format(self.perf_p.pid)
		args = shlex.split(cmdline)
		subprocess.call(args)
		try:
			returncode = self.perf_p.wait(timeout=10)
		except subprocess.TimeoutExpired:
			print_error(tag, ("self.perf_p didn't terminate "
				"after SIGINT, will try SIGKILL but won't wait()"))
			cmdline = ("sudo bash -c 'kill -SIGKILL {}'").format(
					self.perf_p.pid)
			args = shlex.split(cmdline)
			subprocess.call(args)
			returncode = -2

		# When killed with SIGINT, the returncode is 130...
		if returncode != 0 and returncode != 130:
			print_error(tag, ("got non-zero returncode {}").format(
				returncode))

		# elapsedtime should be a float representing the *seconds* elapsed.
		elapsedtime = time.perf_counter() - self.perf_on_time
		lines = ["{}".format(elapsedtime)]
		write_conf_file(lines,
				"{}/perf.elapsedtime".format(self.perf_outputdir),
				overwrite=True)
		self.perf_on_time = None

		# Once we've stopped the perf process, perf.stdout, perf.stderr,
		# and perf.data files should be left in the perf_outputdir.
		# However, the perf.data file will have root:root owner/group,
		# so fix this.
		self.perf_stdout.close()
		self.perf_stderr.close()
		cmdline = "sudo bash -c 'chown {}:{} {}'".format(
			sysconf.trace_user, sysconf.trace_group,
			self.pdata_fname)
		args = shlex.split(cmdline)
		retcode = subprocess.call(args)
		if retcode != 0:
			print_error(tag, ("chown command failed, {} may "
				"still have root:root permissions. {}").format(
				self.pdata_fname, cmdline))
		cmdline = "chmod 644 {}".format(self.pdata_fname)
		args = shlex.split(cmdline)
		subprocess.call(args)

		self.perf_p = None
		self.perf_stdout = None
		self.perf_stderr = None
		self.perf_outputdir = None
		self.perf_tracing_on = False
		self.pdata_fname = None

		return

##############################################################################
# Backs up the specified tracefile and replaces it with a tracefile with
# the same name, but with all events beyond the last event for the CPU whose
# buffer filled up first trimmed.
# tracefile: full path + name of a trace events file.
def trim_trace_file(tracefile):
	tag = 'trim_trace_file'

	if not os.path.exists(tracefile):
		print_error(tag, ("no trace file found at {}").format(tracefile))
		return

	fulltracefile = "{}.full".format(tracefile)
	trimmedtracefile = tracefile
	if os.path.exists(fulltracefile):
		print_error(tag, ("unexpected: {} already exists").format(
			fulltracefile))
		return
	shutil.move(tracefile, fulltracefile)

	# Scan through the full trace file and determine the last line found
	# for each CPU. Currently, all trace events that we care about in
	# the trace file (standard events, user stack trace headers, and user
	# stack trace entries) include a '[001]'-style CPU in them, so we
	# shouldn't accidentally trim off any lines that we care about.
	f = open(fulltracefile, 'r')
	line = f.readline()
	linenum = 1
	cpumap = {}
	while line:
		cpusearch = trace_event_cpu_re.search(line)
		if cpusearch:
			cpu = int(cpusearch.group('cpu'))
			cpumap[cpu] = linenum

		line = f.readline()
		linenum += 1
	f.close()
	
	if len(cpumap) == 0:
		print_error(tag, ("something went wrong, cpumap={}").format(
			cpumap))
		return

	# Find the cpu whose last line is earliest in the trace file:
	earliestlastline = linenum + 1
	earliestcpu = -1
	for (cpu, lastline) in cpumap.items():
		if lastline < earliestlastline:
			earliestlastline = lastline
			earliestcpu = cpu
	print_debug(tag, ("{}: cpumap={}, earliestcpu={}").format(
		fulltracefile, cpumap, earliestcpu))

	# One potential problem here: if the trace buffer happened to fill
	# up after a "<user stack trace>" header has been printed, but
	# before any of the stack entries were saved / printed, then the
	# analysis script might whine. Deal with this later if it's a big
	# problem...

	# Trim the trace file so that it includes the earliest last line,
	# and no more lines after that.
	# Warning: executing subprocess with shell=True is a potential
	# security vulnerability: make sure that this is not exposed to
	# external users!
	f = open(trimmedtracefile, 'w')
	cmdline = ("head --lines={} {}").format(earliestlastline, fulltracefile)
	args = shlex.split(cmdline)
	retcode = subprocess.call(args, stdout=f)
	f.close()
	if retcode != 0:
		print_error(tag, ("command \"{}\" returned non-zero code "
			"{} - trimmed trace file may be corrupted!").format(retcode))
		return

	return

if __name__ == '__main__':
	print_error_exit("not an executable module")
