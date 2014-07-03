# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Dedup benchmark (from parsec).
# 
# Build + setup instructions: do these once / occasionally by hand, not
# done automatically by this script.
#   cd to parsec-3.0 directory (in conf.system_conf.apps_dir)
#   source env.sh
#   parsecmgmt -a fullclean -p parsec.dedup parsec.zlib parsec.ssl
#   parsecmgmt -a fulluninstall -p parsec.dedup parsec.zlib parsec.ssl
#   parsecmgmt -a build -p parsec.dedup &> build.dedup.out
#     Takes a minute or two to complete; check for errors
#   cd pkgs/kernels/dedup/inputs
#   tar xvf input_native.tar
#   tar xvf input_simdev.tar
#   tar xvf input_simlarge.tar; mv media.dat media_simlarge.dat
#   tar xvf input_simmedium.tar; mv media.dat media_simmedium.dat
#   tar xvf input_simsmall.tar; mv media.dat media_simsmall.dat
#   tar xvf input_test.tar
#   cd -
# 
# To build dedup with my own libc, libstdc++, etc., use this build command
# instead of the one above:
#   parsecmgmt -a build -c pjh -p parsec.dedup &> build.dedup.out
# Then, be sure to set dedup_version to amd64-linux.pjh instead of
# amd64-linux.gcc below!
#   I tested that this actually works on 2014-01-06.

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo

dedup_version    = 'amd64-linux.gcc'
#dedup_version    = 'amd64-linux.pjh'

# Note: don't use parsec commands, just run dedup directly - otherwise,
# will get the "unpacking benchmark input" phase before dedup actually
# runs, and other parsec behavior that I don't really want to trace.
dedup_bindir     = ("{}/parsec-3.0/pkgs/kernels/dedup/inst/{}/bin").format(
					apps_dir, dedup_version)
dedup_datadir    = ("{}/parsec-3.0/pkgs/kernels/dedup/inputs").format(apps_dir)
dedup_datafile   = ("{}/FC-6-x86_64-disc1.iso").format(dedup_datadir) #627M
  # With PTE trace events active, using the .iso input overflows trace
  # buffer even with 1.5 GB / core!
#dedup_datafile   = ("{}/media_simlarge.dat").format(dedup_datadir) #185M
  # With this input file and PTE trace events active (and perf tracing
  # on), the trace buffer *nearly* fills up at 512 MB / core - I saw
  # it fill up after the app was done, but when the final trace-off
  # checkpoint was written.
dedup_binfile    = ("{}/dedup").format(dedup_bindir)
dedup_outfile    = ("{}/out.dat").format(dedup_bindir)
dedup_flags      = '-c -p -v -t 1'

#poll_period = 0   # take checkpoints every 'poll' seconds
poll_period = 10   # take checkpoints every 'poll' seconds

##############################################################################

# Runs the actual dedup program. Everything inside of this method will
# be traced.
# Returns a tuple:
#   (True on success, False on error;
#    pid of the top-level dedup process (invalid on error))
def run_dedup(outputdir, dedup_stdout, dedup_stderr, tracer):
	tag = 'run_dedup'

	# http://docs.python.org/3.2/library/subprocess.html
	# pkgs/kernels/dedup/inst/amd64-linux.pjh/bin/dedup -c -p -v -t 1 -i pkgs/kernels/dedup/run/media.dat -o pkgs/kernels/dedup/run/output.dat.ddp
	cmdline = "{} {} -i {} -o {}".format(dedup_binfile, dedup_flags,
			dedup_datafile, dedup_outfile)
	args = shlex.split(cmdline)
	print_debug(tag, ("executing args={} as a child process").format(args))
	print_debug(tag, ("using environment variables: {}").format(
		newlibs_envmap))

	dedup_p = subprocess.Popen(args, stdout=dedup_stdout, stderr=dedup_stderr,
			env=newlibs_envmap)
	  # Will newlibs work even with standard build? Seems to.
	if not dedup_p:
		print_error(tag, ("subprocess.Popen returned "
			"None; cmdline={}").format(cmdline))
		return (False, -1)

	prefix = 'dedup'
	retcode = tracer.trace_wait(dedup_p, poll_period, prefix)

	if retcode == 'full':
		# Count this as an error: don't expect trace buffer to fill
		# up for dedup.
		print_error(tag, ("trace buffer filled up during execution! "
			"Will return error."))
		return (False, -1)
	elif retcode == 'error':
		print_error(tag, ("trace_wait() failed, either due to process "
			"error or trace error; returncode is {}").format(
			dedup_p.returncode))
		return (False, -1)
	elif dedup_p.returncode is None:
		print_error(tag, ("dedup process' returncode not set?!?").format())
		return (False, -1)
	elif dedup_p.returncode != 0:
		print_error(tag, ("dedup process returned error {}").format(
			dedup_p.returncode))
		return (False, -1)

	print_debug(tag, ("dedup process exited successfully, output is "
		"in directory {}").format(outputdir))

	return (True, dedup_p.pid)

def dedup_init(outputdir):
	tag = 'dedup_init'

	dedup_stdout_fname  = "{}/dedup-stdout".format(outputdir)
	dedup_stderr_fname  = "{}/dedup-stderr".format(outputdir)
	dedup_stdout  = open(dedup_stdout_fname, 'w')
	dedup_stderr  = open(dedup_stderr_fname, 'w')

	return (dedup_stdout, dedup_stderr)

def dedup_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

def dedup_exec(outputdir):
	tag = 'dedup_exec'

	(dedup_stdout, dedup_stderr) = dedup_init(outputdir)
	target_pids = []
	tracer = traceinfo('dedup')

	success = tracer.trace_on(outputdir, descr='starting dedup')
	if success:
		(success, dedup_pid) = run_dedup(outputdir, dedup_stdout,
				dedup_stderr, tracer)
	(tracesuccess, buffer_full) = tracer.trace_off(descr='dedup complete')

	if success:
		if not tracesuccess or buffer_full:
			print_error(tag, ("trace buffer filled up before "
				"tracing turned off - considering this an error "
				"here, but echo {} > target_pids file to analyze "
				"trace anyway").format(dedup_pid))
			success = False
			target_pids = []
		else:
			target_pids.append(dedup_pid)
	else:
		print_error(tag, ("trace_on() or run_dedup() returned failure; "
			"will just clean up and return now. target_pids will be "
			"empty, but echo {} > target_pids file to analyze "
			"trace anyway").format(dedup_pid))

	dedup_cleanup([dedup_stdout, dedup_stderr])

	return target_pids

# First arg is "appname" member: used to construct output directory.
dedup_app = app_to_run('dedup', dedup_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
