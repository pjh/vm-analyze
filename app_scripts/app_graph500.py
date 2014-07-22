# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Graph 500 benchmark.
#
# NOTE: with 4 cores, a 1 GB per-core buffer for trace events may not
# be enough for g500_size=24; 1.5 GB per-core buffer does seem to
# be enough.

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import *

#g500_size = 14   # default
#g500_size = 18   # only about 128 MB in memory
#g500_size = 22   # about 1 GB memory
#g500_size = 23   # about 2 GB memory
g500_size = 24    # stjohns: 10.4GB virtual, 9.0GB resident
#g500_size = 25    # stjohns: 19.2GB virtual, 17.5GB resident, about 6 mins
g500_dir =  "{}/graph500".format(apps_dir)
g500_omp =  "{}/omp-csr/omp-csr".format(g500_dir)
g500_seq =  "{}/seq-csr/seq-csr".format(g500_dir)
g500_opts = "-V -s {}".format(g500_size)

#pollperiod = 0   # take checkpoints every 'pollperiod' seconds
pollperiod = 10   # take checkpoints every 'pollperiod' seconds

##############################################################################

# Should be called after tracing has been turned on.
# Returns a tuple:
#   (True on success, False on error;
#    the pid of the g500 process (may be invalid on error))
def run_g500(omp_or_seq, outputdir, g500_stdout, g500_stderr, tracer):
	tag = 'run_g500'

	if omp_or_seq == 'omp':
		which = g500_omp
	elif omp_or_seq == 'seq':
		which = g500_seq
	else:
		print_error(tag, ("invalid omp_or_seq {}").format(omp_or_seq))
		return (False, -1)

	# http://docs.python.org/3.2/library/subprocess.html
	cmdline = "{} {}".format(which, g500_opts)
	args = shlex.split(cmdline)
	print_debug(tag, ("executing args={} as a child process").format(args))
	print_debug(tag, ("using environment variables: {}").format(
		newlibs_envmap))
	g500_p = subprocess.Popen(args, stdout=g500_stdout, stderr=g500_stderr,
			env=newlibs_envmap)
	if not g500_p:
		print_error(tag, ("subprocess.Popen for {} returned "
			"None; cmdline={}").format(which, cmdline))
		return (False, -1)

	if not tracer.perf_on():
		print_error(tag, ("perf_on() failed, but continuing"))
	prefix = "g500{}".format(omp_or_seq)
	retcode = tracer.trace_wait(g500_p, pollperiod, prefix)
	tracer.perf_off()

	if retcode == 'full' or retcode == 'error':
		# Count a full trace buffer as an error - don't expect this
		# for graph500.
		print_error(tag, ("trace_wait returned {}; returncode is {}. "
			"will return error").format(retcode, g500_p.returncode))
		return (False, -1)
	elif g500_p.returncode is None:
		print_error(tag, ("graph500 process' returncode not set?!?").format())
		return (False, -1)
	elif g500_p.returncode != 0:
		print_error(tag, ("graph500 process returned error {}").format(
			g500_p.returncode))
		return (False, -1)

	print_debug(tag, ("graph500 process exited successfully, output is "
		"in directory {}").format(outputdir))

	return (True, g500_p.pid)

# Performs the following steps:
#   - ...
def g500_init(outputdir):
	tag = 'g500_init'

	g500_stdout_fname  = "{}/g500-stdout".format(outputdir)
	g500_stderr_fname  = "{}/g500-stderr".format(outputdir)
	g500_stdout  = open(g500_stdout_fname, 'w')
	g500_stderr  = open(g500_stderr_fname, 'w')

	return (g500_stdout, g500_stderr)

def g500_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

def g500_exec(outputdir, omp_or_seq):
	tag = 'g500_exec'

	choices = ['omp', 'seq']
	if omp_or_seq not in choices:
		print_error(tag, ("invalid omp_or_seq {}, expect it to be in {}. "
			"Returning without any execution").format(
			omp_or_seq, choices))

	# The outputdir already distinguishes between omp or seq.
	(g500_stdout, g500_stderr) = g500_init(outputdir)
	target_pids = []
	tracer = traceinfo('g500')

	success = tracer.trace_on(outputdir, descr='starting graph500')
	if success:
		(success, g500pid) = run_g500(omp_or_seq, outputdir,
				g500_stdout, g500_stderr, tracer)
	(tracesuccess, buffer_full) = tracer.trace_off(descr='graph500 complete')

	if success:
		if not tracesuccess or buffer_full:
			print_error(tag, ("trace buffer filled up before "
				"tracing turned off - considering this an error "
				"here").format())
			success = False
			target_pids = []
		else:
			target_pids.append(g500pid)
	else:
		print_error(tag, ("trace_on() or run_g500() returned failure; "
			"will just clean up and return now. target_pids will be "
			"empty, but manually echo g500pid={} to it if you "
			"wish").format(g500pid))

	g500_cleanup([g500_stdout, g500_stderr])

	return target_pids

def g500_omp_exec(outputdir):
	return g500_exec(outputdir, 'omp')

def g500_seq_exec(outputdir):
	return g500_exec(outputdir, 'seq')

# First arg is "appname" member: used to construct output directory.
g500_omp_app = app_to_run('graph', g500_omp_exec)
g500_seq_app = app_to_run('g500seq', g500_seq_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
