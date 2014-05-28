#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from pjh_utils import *
from process_smaps_lib import *
from vm_regex import *
import vm_common as vm
import datetime
import os
import multiprocessing as mp
import shlex
import shutil
import subprocess
import sys
import time

# Returns: a [list] of the pids of all of the processes that are children
# of the strace process called by this python script. This method is
# pretty brittle. For processes that are still running, the list returned
# by this method should contain at least one pid; a multi-process program
# that is being traced should have more pids in it. If the traced process
# was very short-lived, or if the trace has just ended, then this method
# will return an empty list. None is returned on error.
def find_strace_children(output_dir, filetag):
	tag = "find_strace_children"

	cmdline = "ps -Ho pid,pgid,args"
	fname = "{0}/{1}-ps_hierarchy".format(output_dir, filetag)
	retcode = exec_cmd_save_output(cmdline, fname, fname)
	if retcode != 0:
		print_warning(tag, ("got back non-zero retcode {0} from "
			"exec_cmd_save_output()").format(retcode))
		return None

	ps = open(fname, 'r')
	state = "ps_begin"
	prev_indent = None
	target_indent = None
	children = []

	line = ps.readline()
	while line:
		nextline = ps.readline()
		match = ps_line.match(line)
		if not match:
			if state != "ps_begin":
				print_error_exit(tag, ("failed to match ps line! {0}").format(
					line))
			else:
				(pid, pgid, spaces, cmd) = (None, None, None, None)
				indent = None
		else:
			(pid, pgid, spaces, cmd) = match.groups()
			pid = int(pid)
			pgid = int(pgid)
			indent = len(spaces)
			#print_debug(tag, ("pid {0}; pgid {1}; spaces {2} (len {3}); "
			#	"cmd \"{4}\"").format(pid, pgid, spaces, len(spaces), cmd))

		#print_debug(tag, ("pre-state: {0}").format(state))
		if state == "ps_begin":
			state = "ps_shell"
		elif state == "ps_shell":
			if (pid != pgid or indent != 1 or "sh" not in cmd):
				print_error_exit(tag, ("unexpected values for state={0}: "
					"pid {1}, pgid {2}, indent {3}, cmd "
					"\"{4}\"").format(state, pid, pgid, indent, cmd))
			state = "ps_python"
		elif state == "ps_python":
			cmd_args = shlex.split(cmd)
			#print_warning(tag, ("basename cmd_args[0]: {0}").format(
			#	os.path.basename(cmd_args[0])))
			if (pid != pgid or
				(os.path.basename(cmd_args[0]))[0:6] != "python" or 
				indent != prev_indent + 2):
				print_error_exit(tag, ("unexpected values for state={0}: "
					"pid {1}, pgid {2}, indent {3}, cmd "
					"\"{4}\"").format(state, pid, pgid, indent, cmd))
			state = "ps_strace"
		elif state == "ps_strace":
			if cmd == "[strace] <defunct>":
				# (python note: 'if cmd is "[strace] <defunct>"' doesn't
				#  work here, I don't know why...)
				target_indent = indent + 2
				state = "ps_post_target"
			elif (cmd[0:6] != "strace" or
				indent != prev_indent + 2):
				print_error_exit(tag, ("unexpected values for state={0}: "
					"pid {1}, pgid {2}, indent {3}, cmd "
					"\"{4}\"").format(state, pid, pgid, indent, cmd))
			else:   # expected case
				target_indent = indent + 2
				state = "ps_target"
		elif state == "ps_target":
			if indent < target_indent:
				# Sometimes it looks like we execute this method and the
				# strace process has started, but not the traced process.
				# When this happens, just break and this method will
				# return no children. The ps output should look like this:
				#   python3 ./capture_strace.py ...
				#     strace -f -o strace-captures/firefox/strace ...
				#     /bin/sh -c ps -Ho pid,pgid,args
				#       ps -Ho pid,pgid,args
				if indent == prev_indent and cmdline in line:
					print_warning(tag, ("no strace children found in ps "
						"hierarchy - expect this to only happen for first "
						"\"iteration\" (filetag={0})").format(filetag))
					break
				print_error_exit(tag, ("invalid indent {0} for state {1} - "
					"target_indent is {2}").format(indent, state,
					target_indent))

			# At this point, based on the indentation level and the
			# current state, we can be certain that the process represented
			# by this line is either the process that we are capturing or
			# a child of the process that we are capturing. As soon as the
			# indent level of the next line goes below the target indent
			# level, we move out of the ps_target state and never come back
			# to it.
			children.append(pid)

			if not nextline:
				print_warning(tag, ("under current strace / ps expectations, "
					"don't we expect nextline to always exist here? Could be "
					"that ps/shell commands got a lower pid than the captured "
					"process...").format())
			else:
				match = ps_line.match(nextline)
				if not match:
					print_error_exit(tag, ("nextline match failed "
						":(").format())
				(pid, pgid, spaces, cmd) = match.groups()
				pid = int(pid)
				pgid = int(pgid)
				indent = len(spaces)
				if indent == target_indent:
					print_error_exit(tag, ("unexpected: indent {0} == "
						"target_indent! This means that strace spawned "
						"multiple top-level processes??").format(indent))
				elif indent < target_indent:
					state = "ps_post_target"
				else:
					state = "ps_target"
		elif state == "ps_post_target":
			break
		else:
			print_error_exit(tag, ("unexpected state: {0}").format(
				state))
		#print_debug(tag, ("post-state: {0}").format(state))

		prev_indent = indent
		line = nextline
	
	ps.close()
	
	#cmdline = ("ps -eo pid,pgid,args --sort pgid | grep {0}".format(
	#	pid))
	#fname = "{0}/{1}-ps_{2}".format(output_dir, name, pid)
	#retcode = exec_cmd_save_output(cmdline, fname, fname)
	#if retcode != 0:
	#	print_warning(tag, ("got back non-zero retcode {0} from "
	#		"exec_cmd_save_output()").format(retcode))
	#	return None
	
	# TODO: use this command or something similar to get pids of
	#   all processes in the "process group" of this process!
	#   ps -eo pid,pgid,args --sort pgid | grep 30006 | cut -d ' ' -f 1
	#   Note: as a sanity check, call this command again without the
	#   "cut", and make sure that the entry with the top-level pid also
	#   has that pid as its pgid! If not, then top-level pid that we're
	#   examining here is in another process group, which doesn't seem
	#   right.
	#     Actually, the pgid is probably going to be that of this python
	#     process, not the top-level process that we just created! So,
	#     use that pgid instead, or parse the tree output of ps:
	#     ps -ejH. Note that ps is better than pstree because ps
	#     ignores threads, while pstree will always include application
	#     level threads.

	# Note: the python "multiprocessing" package has a function called
	# "active_children()", but I'm pretty sure that it can only be used
	# to get child processes that were started explicitly by this script
	# using the other methods in that package - I tried and it doesn't
	# return the children of a process started with Popen(), etc.

	return children

def copy_proc_files(output_dir, pid, iteration):
	tag = "copy_proc_files"

	pid = str(pid)
	iteration = str(iteration).zfill(3)
	  # http://stackoverflow.com/questions/339007/python-nicest-way-to-pad-zeroes-to-string
	proc_root = "/proc"
	proc_files = ["smaps", "maps", "status", "stat"]
	for fname in proc_files:
		src_fname = ("{0}/{1}/{2}").format(proc_root, pid, fname)
		#dst_fname = ("{0}/{1}-{2}-{3}").format(
		#	output_dir, iteration, fname, pid)
		dst_fname = ("{0}/{1}-{2}").format(
			output_dir, iteration, fname)
		#print_debug(tag, ("src_fname={0}  dst_fname={1}").format(
		#	src_fname, dst_fname))
		vm.copy_proc_file_old(src_fname, dst_fname)
	save_pstree("{}/{}-pstree".format(output_dir, fname))

	cmdline = "ls -ahl {0}/{1}/".format(proc_root, pid)
	dst_fname = "{0}/{1}-ls-ahl".format(output_dir, iteration)
	retcode = exec_cmd_save_output(cmdline, dst_fname, dst_fname)
	if retcode != 0:
		print_warning(tag, ("got back non-zero retcode {0} from "
			"exec_cmd_save_output()").format(retcode))

	return

def run_app(prog_args, output_dir, delay, interval):
	tag = "run_app"

	strace_prefix = ""  #"strace-"
	strace_suffix = ""  #".strace"
	prog_out_suffix = ""  #".out"
	strace_fname = "{0}/{1}{2}{3}".format(
		output_dir, strace_prefix, "strace", strace_suffix)

	# strace arguments:
	#   -o: file to write output to.
	#   -f: trace forked child processes. Does this work for child
	#     processes created with clone() as well?
	#   -ff: trace forked child processes, and output each trace to
	#     a separate file.
	#   -r: print relative timestamps (time between successive syscalls).
	#   -t: print time-of-day. Also: -tt, -ttt.
	#   -T: record time spent IN each system call.
	#   -p: attach to an already-running pid.
	# Other notes:
	#   Output differs when just -f is used (and redirected by shell to
	#     a file) and when -f -o are both used! Plan to use the second
	#     one, which puts a pid at the very beginning of every output
	#     line:
	#       600   brk(0)                            = 0xaad000
	#     rather than this:
	#       brk(0)                                  = 0x96f000
	#       ...
	#       clone(Process 519 attached
	#       child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f5df68ca9d0) = 519
	#       [pid   518] rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
	#       [pid   518] ...
	#   UGH: when -f is used with google-chrome, strace fails:
	#     "Failed to move to new PID namespace: Operation not permitted"
	#     Problem: not exactly sure, but workaround is to use --no-sandbox
	#       flag to google-chrome.
	#     https://code.google.com/p/chromium/issues/detail?id=31077
	#     https://code.google.com/p/chromium/issues/detail?id=138505
	#     http://comments.gmane.org/gmane.linux.vserver/19625
	#     -F flag works slightly better/differently?
	#  google-chrome: behavior may also be weird when chrome is already
	#    running (e.g. new tab is loaded, then "Process 32704 detached"
	#    message comes and strace stops). Kill all chrome processes
	#    before starting fresh trace, just to be safe?
	#strace_cmd = ("strace -o {0}").format(strace_fname)
	strace_cmd = ("strace -f -o {0}").format(strace_fname)
	strace_args = shlex.split(strace_cmd)

	stdout_fname = "{0}/{1}{2}{3}".format(
		output_dir, strace_prefix, "stdout", prog_out_suffix)
	stderr_fname = "{0}/{1}{2}{3}".format(
		output_dir, strace_prefix, "stderr", prog_out_suffix)
	stdout_f = open(stdout_fname, 'w')
	stderr_f = open(stderr_fname, 'w')

	cmd_fname = "{0}/{1}".format(output_dir, "command")
	cmd_f = open(cmd_fname, 'w')
	cmd_f.write(("{0}\n").format(" ".join(prog_args)))
	cmd_f.close()

	args = strace_args + prog_args
	arg_str = " ".join(args)
	print_debug(tag, ("arg_str: {0}".format(arg_str)))

	TIMEOUT = 300   # set to 0 to disable...
	iterations = 0
	waited = 0
	poll_interval = interval
	retcode = None
	begin_time = time.time()
	p = subprocess.Popen(args, stdout=stdout_f, stderr=stderr_f)
	  # http://docs.python.org/3/library/subprocess.html?highlight=subprocess#popen-objects
	strace_pid = p.pid
	print_debug(tag, ("started \"strace {0}\" - pid of strace is "
		"{1}").format(prog_args[0], strace_pid))
	all_pids = set()
	
	if delay > 0:
		print(("sleeping for {0} seconds before copying /proc files for traced process "
			"and its children").format(delay))
		time.sleep(delay)
		waited += delay

	while retcode is None:
		pids = find_strace_children(output_dir, str(waited).zfill(3))
		print_debug(tag, ("waited={0}: pids {1}").format(waited,
			pids))
		if pids is None:
			print_error_exit(tag, ("find_strace_children() returned "
				"error").format())
		# While the process has not terminated, periodically capture
		# its /proc/pid/smaps and other files that we care about.
		# Bonus: I think that because Popen() is like a fork+exec and
		# poll() is like a waitpid(), the /proc files for the process
		# will still be present in its pid dir EVEN IF the process
		# has already finished, because it has not been cleaned up by
		# its parent yet! This means that if the process' execution
		# time is shorter than the polling interval, we can still capture
		# its final smaps state.
		#   I verified that this seems true by putting another call to
		#   copy_proc_files() after this while loop, which causes a
		#   "IOError: [Errno 2] No such file or directory" exception to
		#   be raised. This has yet to happen when trying to copy the
		#   /proc files from within this loop.
		for pid in pids:
			all_pids.add(pid)
			pid_dir = "{0}/{1}".format(output_dir, pid)
			if not os.path.exists(pid_dir):
				os.mkdir(pid_dir)
			copy_proc_files(pid_dir, pid, waited)
		time.sleep(poll_interval)
		retcode = p.poll()
			# returns None if process not terminated yet. Remember, this
			# is the strace process, not the traced process (it may have
			# already terminated, in which case the strace will be a
			# zombie, waiting to be polled on!).
		iterations += 1
		waited += poll_interval
		if (retcode is None and 
			(TIMEOUT > 0 and waited >= TIMEOUT)):
			p.kill()   # SIGTERM can be blocked, SIGKILL can't.
			#p.terminate()   # SIGTERM can be blocked, SIGKILL can't.
			print_warning(tag, ("sent SIGKILL to strace process {0} after "
				"{1} seconds").format(strace_pid, TIMEOUT))
			print_warning(tag, ("TODO: find python commands to kill all "
				"child threads/pids as well!").format())
			retcode = -1
	end_time = time.time()
	if retcode is None or retcode != 0:
		print_warning(tag, ("command \"{0}\" had non-zero code {1} - "
			"error during execution, or timeout.").format(prog_args, retcode))

	elapsed = datetime.timedelta(seconds=(end_time - begin_time))
	print(("{0}").format(arg_str))
	print(("\tstrace file: {0}").format(strace_fname))
	print(("\telapsed time: {0}").format(str(elapsed)))
	print_debug("\t", "all_pids: {0}".format(all_pids))

	stdout_f.close()
	stderr_f.close()

	return (iterations, all_pids)

def post_process(prog_args, output_dir, iterations, delay, interval, all_pids):
	tag = "post_process"

	prog_short_name = os.path.basename(prog_args[0])

	if len(all_pids) == 0:
		print(("No /proc files were captured from child processes during "
			"the strace - process was too short-lived! strace file is "
			"still valid though.").format())

	for pid in all_pids:
		pid_dir = "{0}/{1}".format(output_dir, pid)
		pid_pdf = PdfPages("{0}/VASpace-plots.pdf".format(pid_dir))
		for i in range(delay, delay + iterations*interval, interval):
			iter_str = str(i).zfill(3)
			smaps_fname = ("{0}/{1}-smaps").format(pid_dir, iter_str)
			if not os.path.exists(smaps_fname):
				print_warning(tag, ("didn't find smaps_fname at {0}; "
					"means that child process died during "
					"execution? Or means that child process hadn't "
					"started yet for first iteration...".format(
					smaps_fname)))
				continue
			plot_fname = ("{0}/{1}-VASpace-{2}").format(
				pid_dir, prog_short_name, iter_str)   # .png will be attached

			iter_pdf = PdfPages("{0}/VASpace-plot-{1}.pdf".format(
				pid_dir, iter_str))
			pdf_list = [pid_pdf, iter_pdf]

			smaps_file_to_vm_plot(pid_dir, smaps_fname, prog_short_name,
				plot_fname, pdf_list)

			iter_pdf.close()

		pid_pdf.close()

	return

def setup(prog_args):
	tag = "setup"

	prog_basename = os.path.basename(prog_args[0])
	if not prog_basename:
		print_error_exit(tag, ("got null basename from first prog_arg - "
			"{0}").format(prog_args[0]))

	top_dir = "strace-captures"
	if not os.path.exists(top_dir):
		os.mkdir(top_dir)
	dir_prefix = ""
	dir_suffix = ""
	output_dir = "{0}/{1}{2}{3}".format(top_dir, dir_prefix,
		prog_basename, dir_suffix)
	if os.path.exists(output_dir):
		print_warning(tag, ("output_dir \"{0}\" already exists - may "
				"overwrite files!").format(output_dir))
	else:
		os.mkdir(output_dir)

	return output_dir

def usage():
	print(("usage: {0} <command> [args-to-command]").format(sys.argv[0]))
	print(("\tCurrently prints all output to stdout"))
	sys.exit(1)

def parse_args(argv):
	tag = "parse_args"

	if len(argv) < 2:
		usage()
	prog_args = argv[1:len(argv)]
	#print_debug(tag, ("argv: {0}").format(argv))
	#print_debug(tag, ("prog_args: {0}").format(prog_args))

	return prog_args

# Main:
if __name__ == '__main__':
	tag = "main"

	prog_args = parse_args(sys.argv)
	output_dir = setup(prog_args)
	delay = 3
	interval = 10  # arbitrary for now...
	(iterations, all_pids) = run_app(prog_args, output_dir, delay, interval)
	post_process(prog_args, output_dir, iterations, delay, interval, all_pids)

	sys.exit(0)
else:
	print("Must run stand-alone")
	usage()
	sys.exit(1)
