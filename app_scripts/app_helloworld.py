# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Application script for Hello, World (and minor variants).
# 
# Build + setup instructions: do these once / occasionally by hand, not
# done automatically by this script.
#   cd virtual/apps/test-programs
#   Edit Makefile
#     Decide if you want to use my own built libc, or the system default
#     libc...
#   make all

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo
import conf.system_conf as sc

TEST_PROGRAMS_DIR = "{}/test-programs".format(sc.apps_dir)
HELLO_WORLD = "{}/hello-world".format(TEST_PROGRAMS_DIR)
HELLO_WORLD_STATIC = "{}/hello-world-static".format(TEST_PROGRAMS_DIR)

HELLO_SLEEPTIME = 2
  # Our hello-world programs print a message, than sleep for a specified
  # number of seconds, then print another message and exit. This is done
  # to ensure that various parts of the standard library are touched.

##############################################################################

# Tracing should already be activated when this method is called.
# Returns a tuple:
#   (True on success, False on error;
#    pid of the hello-world process on success)
def run_hw(static_dynamic, outputdir, hw_stdout, hw_stderr, tracer):
	tag = 'run_hw'

	if static_dynamic == 'dynamic':
		hw_cmd = "{} {}".format(HELLO_WORLD, HELLO_SLEEPTIME)
	elif static_dynamic == 'static':
		hw_cmd = "{} {}".format(HELLO_WORLD_STATIC, HELLO_SLEEPTIME)
	else:
		print_error(tag, ("invalid: static_dynamic={}").format(
			static_dynamic))
		return (False, -1)

	args = shlex.split(hw_cmd)
	print_debug(tag, ("executing hw_cmd=\"{}\"").format(hw_cmd))

	hw_p = subprocess.Popen(args, stdout=hw_stdout, stderr=hw_stderr)
	if not hw_p:
		print_error(tag, ("subprocess.Popen returned None; "
			"hw_cmd={}").format(hw_cmd))
		return (False, -1)

	prefix = 'helloworld'
	retcode = tracer.trace_wait(hw_p, None, prefix)
	if retcode != "success":
		# Assume that trace buffer filling up is an error for this app.
		print_error(tag, ("trace_wait() returned {}, either due to process "
			"error or trace error; hw_p.returncode is {}").format(
			retcode, hw_p.returncode))
		return (False, -1)
	elif hw_p.returncode is None:
		print_error(tag, ("hw process' returncode not set?!?").format())
		return (False, -1)
	elif hw_p.returncode != 0:
		print_error(tag, ("hw process returned error {}").format(
			hw_p.returncode))
		return (False, -1)

	print_debug(tag, ("hw process exited successfully, output is "
		"in directory {}").format(outputdir))

	return (True, hw_p.pid)

def hw_init(outputdir):
	tag = 'hw_init'

	hw_stdout_fname  = "{}/hw-stdout".format(outputdir)
	hw_stderr_fname  = "{}/hw-stderr".format(outputdir)
	hw_stdout  = open(hw_stdout_fname, 'w')
	hw_stderr  = open(hw_stderr_fname, 'w')

	return (hw_stdout, hw_stderr)

def hw_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

# Returns: a target_pids list containing the pid of the hello-world
# process, or an empty list on error.
def hw_exec(outputdir, static_dynamic):
	tag = 'hw_exec'

	if static_dynamic == 'dynamic':
		name = 'helloworld'
	elif static_dynamic == 'static':
		name = 'helloworld-static'
	else:
		print_error(tag, ("invalid arg: static_dynamic={}").format(
			static_dynamic))
		return []

	(hw_stdout, hw_stderr) = hw_init(outputdir)
	tracer = traceinfo(name)
	target_pids = []

	success = tracer.trace_on(outputdir, "starting {}".format(name),
			use_perf=True)
	if not success:
		print_error(tag, ("trace_on failed, returning [] now").format())
		hw_cleanup([hw_stdout, hw_stderr])
		return []

	(success, hw_pid) = run_hw(static_dynamic, outputdir, hw_stdout,
			hw_stderr, tracer)

	if success and hw_pid > 1:
		target_pids.append(hw_pid)
		print_debug(tag, ("run_hw() successful, target_pids: "
			"{}").format(target_pids))
	else:
		print_error(tag, ("run_hw() returned {} and {}; will "
			"return empty target_pids list").format(success, hw_pid))

	(tracesuccess, buffer_full) = tracer.trace_off(
			descr="{} done".format(name))
	if not tracesuccess or buffer_full:
		print_error(tag, ("trace buffer filled up before "
			"tracing turned off - considering this an error "
			"here").format())
		success = False
		target_pids = []

	hw_cleanup([hw_stdout, hw_stderr])

	return target_pids

def hw_dynamic_exec(outputdir):
	return hw_exec(outputdir, 'dynamic')

def hw_static_exec(outputdir):
	return hw_exec(outputdir, 'static')

# First arg is "appname" member: used to construct output directory.
helloworld_app = app_to_run('hello', hw_dynamic_exec)
helloworld_static_app = app_to_run('hellostatic', hw_static_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
