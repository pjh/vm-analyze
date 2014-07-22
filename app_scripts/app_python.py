# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Python script to run another Python script as a test application.
# 
# Build + setup instructions: do these once / occasionally by hand, not
# done automatically by this script.
#   Ensure that py_version is in your path.
#   ...
#   Run the firefox app script first, then copy its trace-events-full
#     file and its target_pids file to match the locations specified
#     by py_inputpids and py_inputfile below.
#   
#
# Note: this script uses timeout features that were added to Python 3.3
# (available in Ubuntu 13.04) - if this is a problem, they should be
# fairly easy to eliminate from the code, just search for "timeout".

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo

py_version = 'python3.3'
py_scriptname = "{}/analyze_trace.py".format(scripts_dir)
	# Run the analyze_trace.py script in the vm-analyze repository
	# directly; don't try to copy it to another location and run
	# it from there, as it makes the module imports / dependencies
	# too hard to deal with.
py_app_dir = "{}/pythonapp".format(appscripts_dir)
py_inputpids = "{}/ffox-target-pids".format(py_app_dir)
py_inputfile = "{}/ffox-trace-events-full".format(py_app_dir)
py_outputdir = py_app_dir
py_cmd = ("{} {} -a ffox -p {} {} {}").format(py_version,
		py_scriptname, py_inputpids, py_inputfile, py_outputdir)
	# Enable (or leave enabled) options that will require more memory:
	# physical page events.
	# As of 20140703, running analyze_trace.py on a 420 MB trace-events-full
	# from a firefox run (visiting 30 websites) with Rss events enabled
	# takes just over five minutes, with ~600 MB virtual and ~450 MB physical
	# memory used during the analysis.

poll_period = 10

##############################################################################

# Tracing should already be activated when this method is called - it
# will call trace_wait() while the python script runs.
# Returns a tuple:
#   (True on success, False on error;
#    pid of the python process on success)
def run_py_script(outputdir, py_stdout, py_stderr, tracer):
	tag = 'run_py_script'

	# http://docs.python.org/3.2/library/subprocess.html
	args = shlex.split(py_cmd)
	print_debug(tag, ("executing py_cmd=\"{}\"").format(py_cmd))

	py_p = subprocess.Popen(args, stdout=py_stdout, stderr=py_stderr)
	if not py_p:
		print_error(tag, ("subprocess.Popen returned None; "
			"py_cmd={}").format(py_cmd))
		return (False, -1)

	if not tracer.perf_on():
		print_error(tag, ("perf_on() failed, but continuing"))
	prefix = 'py'
	retcode = tracer.trace_wait(py_p, poll_period, prefix)
	tracer.perf_off()

	if retcode != "success":
		# Assume that trace buffer filling up is an error for this app.
		print_error(tag, ("trace_wait() returned {}, either due to process "
			"error or trace error; py_p.returncode is {}").format(
			retcode, py_p.returncode))
		return (False, -1)
	elif py_p.returncode is None:
		print_error(tag, ("py process' returncode not set?!?").format())
		return (False, -1)
	elif py_p.returncode != 0:
		print_error(tag, ("py process returned error {}").format(
			py_p.returncode))
		return (False, -1)

	print_debug(tag, ("py process exited successfully, output is "
		"in directory {}").format(outputdir))

	return (True, py_p.pid)

def py_init(outputdir):
	tag = 'py_init'

	py_stdout_fname  = "{}/python-stdout".format(outputdir)
	py_stderr_fname  = "{}/python-stderr".format(outputdir)
	py_stdout  = open(py_stdout_fname, 'w')
	py_stderr  = open(py_stderr_fname, 'w')

	return (py_stdout, py_stderr)

def py_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

# Returns: a target_pids list containing the top-level pid of the
# python process, or an empty list on error.
def py_exec(outputdir):
	tag = 'py_exec'

	target_pids = []

	(py_stdout, py_stderr) = py_init(outputdir)
	tracer = traceinfo('python')

	success = tracer.trace_on(outputdir, "starting python")
	if not success:
		print_error(tag, ("trace_on failed, returning [] now").format())
		py_cleanup([py_stdout, py_stderr])
		return []

	(success, py_pid) = run_py_script(outputdir, py_stdout, py_stderr,
			tracer)

	if success and py_pid > 1:
		target_pids.append(py_pid)
		print_debug(tag, ("run_py_script() successful, target_pids: "
			"{}").format(target_pids))
	else:
		print_error(tag, ("run_py_script() returned {} and {}; will "
			"return empty target_pids list").format(success, py_pid))

	(tracesuccess, buffer_full) = tracer.trace_off(
			descr="python done".format())
	if not tracesuccess or buffer_full:
		print_error(tag, ("trace buffer filled up before "
			"tracing turned off - considering this an error "
			"here, but echo {} > target_pids file to analyze "
			"trace anyway").format(py_pid))
		success = False
		target_pids = []

	py_cleanup([py_stdout, py_stderr])

	return target_pids

# First arg is "appname" member: used to construct output directory.
python_app = app_to_run('python', py_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
