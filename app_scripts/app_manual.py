# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Special "application" that easily performs common tracing steps, but
# allows application itself to be executed manually.

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo
import readline

##############################################################################

# Returns: a list of "target" pids explicitly input by the user.
def manual_loop(output_dir, manual_stdout, manual_stderr):
	tag = 'manual_loop'

	# Options for reading input from shell:
	#   http://docs.python.org/3/library/functions.html#input
	#   http://docs.python.org/3/library/cmd.html
	print(("NOTE: you should add at least one \"target pid\" for the\n"
		"app(s) you run manually, otherwise later steps may fail!").format())
	prompt = ("'t' = toggle tracing; '<name>' = take named checkpoint; "
			"<Enter> = take checkpoint; 'p' = add target pid; "
			"Ctrl-d = quit\n--> ").format()

	tracer = traceinfo('manualapp')
	target_pids = []
	success = True
	trace_active = False
	cpnum = 1
	while(True):
		try:
			cmd = input(prompt)
			if cmd == 't':
				if not trace_active:
					success = tracer.trace_on(output_dir,
							descr='manual toggle on')
					if not success:
						print_error(tag, ("trace_on failed!").format())
						break
					trace_active = True
					print(("\ttoggled tracing ON; run your app in another "
						"shell!"))
				else:
					(success, buffer_full) = tracer.trace_off(
							descr='manual toggle off')
					trace_active = False
					if buffer_full:
						print("\tWARNING: trace buffer filled before "
							"trace turned off!")
					if not success:
						break
					print("\ttoggled tracing OFF")
			elif cmd == 'p':
				pidprompt = ("Enter target pid> ").format()
				pidstr = input(pidprompt)
				try:
					pid = int(pidstr)
					target_pids.append(pid)
					print(("\ttarget_pids list: {}").format(target_pids))
				except ValueError:
					print(("\tinvalid pid input \"{}\"").format(
						pidstr))
			else:
				if trace_active:
					if cmd == '':
						cpname = "checkpoint{}".format(
								str(cpnum).zfill(3))
						cpnum += 1
					else:
						cpname = cmd
					retcode = tracer.trace_checkpoint(cpname)
					if retcode == 'full':
						print("\ttrace buffer is full! No checkpoint taken")
					elif retcode == 'error':
						print("\terror while taking checkpoint")
						success = False
						break
					print("\ttook checkpoint: {}".format(cpname));
				else:
					print("\tcan't take checkpoint, tracing is off");

		except EOFError:
			print('')   # newline after prompt
			break
	
	if trace_active:
		(success, buffer_full) = tracer.trace_off(
				descr='final manual toggle off')
		trace_active = False
		if not success or buffer_full:
			print("\tWARNING: trace buffer filled before trace "
					"turned off!")
		print("\ttoggled tracing OFF")

	if not success:
		print_error(tag, ("trace_off may have failed, make sure that "
			"kernel tracing is not still active!").format())

	return target_pids

def manual_init(output_dir):
	tag = 'manual_init'

	manual_stdout_fname  = "{}/manual-stdout".format(output_dir)
	manual_stderr_fname  = "{}/manual-stderr".format(output_dir)
	manual_stdout  = open(manual_stdout_fname, 'w')
	manual_stderr  = open(manual_stderr_fname, 'w')

	return (manual_stdout, manual_stderr)

def manual_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

def manual_exec(output_dir):
	tag = 'manual_exec'

	(manual_stdout, manual_stderr) = manual_init(output_dir)
	target_pids = manual_loop(output_dir, manual_stdout, manual_stderr)
	manual_cleanup([manual_stdout, manual_stderr])

	return target_pids

manual_app = app_to_run('manualapp', manual_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
