# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Linux kernel build.

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo

# null: this script will explicitly build the source directory once before
#   activating tracing, then will run a second "null" build (that will
#   still take several minutes and spawn many child make processes) while
#   tracing is on.
# full: this script will explicitly clean the source directory, then will
#   run a full build with tracing enabled. It is unlikely that the kernel
#   trace buffer will be able to contain the entire build trace.
# default: this script won't explicitly clean or build the kernel source
#   first, it will just enter the source directory and run "make", with
#   whatever state is already there.
#BUILDTYPE = 'null'
#BUILDTYPE = 'full'
#BUILDTYPE = 'default'
BUILDTYPE = 'onefile'

#poll_period = 0   # take checkpoints every 'poll' seconds
poll_period = 10   # take checkpoints every 'poll' seconds
LINUXSRCDIR =  "{}/linux-3.9.4".format(apps_dir)

# For the 'onefile' BUILDTYPE, this file will be "modified" before
# the kernel build is kicked off. Currently, the modification is
# simply appending some preprocessor macros, so it doesn't really
# have any effect on the output of the kernel build, but makes it
# more "realistic".
TARGETFILE = 'kernel/fork.c'

##############################################################################

def touch_kernelfile():
	tag = 'touch_kernelfile'

	fname = "{}/{}".format(LINUXSRCDIR, TARGETFILE)
	try:
		f = open(fname, 'a')
	except OSError:
		print_error(tag, ("could not open {} for appending").format(
			fname))
		return False

	f.write("\n")
	f.write("#undef ABRACADABRA\n")
	f.write("#define ABRACADABRA\n")
	f.write("#undef ABRACADABRA")

	f.close()
	return True

# This method assumes that we have already chdir'd into LINUXSRCDIR.
# If buildtype == 'traced', then this method assumes that tracing has
# already been turned on and will take checkpoints every poll_period
# seconds.
# Returns a tuple:
#   (True on success, False on error;
#    pid of the top-level kernel make process (invalid on error))
def run_kernelbuild(outputdir, build_stdout, build_stderr, buildtype,
		tracer):
	tag = 'run_kernelbuild'

	traced = False
	clean = False
	if buildtype == 'null':
		pass
	elif buildtype == 'full':
		clean = True   # next build will be full traced build
	#elif buildtype == 'default':
	#	pass
	elif buildtype == 'traced':
		# Trace this build; may be null, full, or default
		traced = True
	else:
		print_error(tag, ("invalid buildtype {}").format(buildtype))
		return (False, -1)

	if clean:
		print_error(tag, ("about to clean the kernel directory - are "
			"you sure about this?!? A full build takes over an hour! "
			"Explicitly disable this check if you're sure.").format())
		return (False, -1)

	# http://docs.python.org/3.2/library/subprocess.html
	cmdline = 'make'
	if clean:
		cmdline += ' clean'
	args = shlex.split(cmdline)
	print_debug(tag, ("args: {}").format(args))
	'''
	print_debug(tag, ("using environment variables: {}").format(
		newlibs_envmap))
	build_p = subprocess.Popen(args, stdout=build_stdout, stderr=build_stderr,
			env=newlibs_envmap)
	if not build_p:
		print_error(tag, ("subprocess.Popen for {} returned "
			"None; cmdline={}").format(which, cmdline))
		return (False, -1)
	'''
	print_debug(tag, ("running kernel build with unchanged environment "
		"variables").format())
	build_p = subprocess.Popen(args, stdout=build_stdout,
			stderr=build_stderr)
	if not build_p:
		print_error(tag, ("subprocess.Popen returned None, cmdline="
			"{}").format(cmdline))
		return (False, -1)

	prefix = 'kernelbuild'
	if traced:
		poll = poll_period
	else:
		# trace_wait() won't take any checkpoints, will just wait.
		poll = None
	retcode = tracer.trace_wait(build_p, poll, prefix)

	if retcode == 'error':
		print_error(tag, ("trace_wait() failed, either due to process "
			"error or trace error; returncode is {}").format(
			build_p.returncode))
		return (False, build_p.pid)
	elif retcode == 'full':
		# For kernelbuild, still assume success on full trace buffer.
		print_debug(tag, ("trace_wait returned {}: this is often "
			"expected for a kernel build (due to all of its forked "
			"processes), so assume success here").format(retcode))
	elif build_p.returncode is None:
		print_error(tag, ("make process' returncode not set?!?").format())
		return (False, build_p.pid)
	elif build_p.returncode != 0:
		print_error(tag, ("make process returned error {}").format(
			build_p.returncode))
		return (False, build_p.pid)

	print_debug(tag, ("make process exited successfully, output is "
		"in directory {}").format(outputdir))
	return (True, build_p.pid)

def build_init(outputdir, buildtype):
	tag = 'build_init'

	build_stdout_fname  = "{}/build-{}-stdout".format(outputdir, buildtype)
	build_stderr_fname  = "{}/build-{}-stderr".format(outputdir, buildtype)
	build_stdout  = open(build_stdout_fname, 'w')
	build_stderr  = open(build_stderr_fname, 'w')

	return (build_stdout, build_stderr)

def build_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

def kernelbuild_exec(outputdir):
	tag = 'kernelbuild_exec'

	# Easiest to just cd to the linux source directory for the duration
	# of this script, then cd back when we're done.
	prev_cwd = set_cwd(LINUXSRCDIR)
	if not prev_cwd:
		print_error(tag, ("set_cwd failed, returning now"))
		return

	success = True
	tracer = traceinfo('kernelbuild')

	if BUILDTYPE == 'null':
		print_debug(tag, ("BUILDTYPE {}: building once without tracing "
			"so that next build will be a 'null' build").format(BUILDTYPE))
		(build_stdout, build_stderr) = build_init(outputdir, 'prelim')
		success = run_kernelbuild(outputdir, build_stdout,
					build_stderr, BUILDTYPE, tracer)
		build_cleanup([build_stdout, build_stderr])
	elif BUILDTYPE == 'full':
		print_debug(tag, ("BUILDTYPE {}: building clean without tracing, "
			"so that next build will be a full build").format(BUILDTYPE))
		(build_stdout, build_stderr) = build_init(outputdir, 'clean')
		success = run_kernelbuild(outputdir, build_stdout,
					build_stderr, BUILDTYPE, tracer)
		build_cleanup([build_stdout, build_stderr])
	elif BUILDTYPE == 'onefile':
		print_debug(tag, ("BUILDTYPE {}: calling touch_kernelfile(), "
			"then will perform traced build").format(BUILDTYPE))
		success = touch_kernelfile()
	elif BUILDTYPE == 'default':
		print_debug(tag, ("BUILDTYPE {}: building with tracing "
			"immediately, using whatever state source dir was in").format(
			BUILDTYPE))
	else:
		print_error(tag, ("invalid BUILDTYPE {}, returning now").format(
			BUILDTYPE))
		unset_cwd(prev_cwd)
		return

	if not success:
		print_error(tag, ("initial {} operation failed, returning "
			"now").format(BUILDTYPE))
		unset_cwd(prev_cwd)
		return

	target_pids = []
	(build_stdout, build_stderr) = build_init(outputdir, 'traced')
	success = tracer.trace_on(outputdir, descr='starting kernelbuild',
			use_perf=True)
	if success:
		(success, build_pid) = run_kernelbuild(outputdir, build_stdout,
					build_stderr, 'traced', tracer)
	(tracesuccess, buffer_full) = tracer.trace_off(
			descr='kernelbuild complete')

	if success:
		if not tracesuccess:
			print_error(tag, ("tracesuccess is False, this is an "
				"error; returning empty target_pids (without "
				"top-level make pid {}").format(build_pid))
			success = False
			target_pids = []
		elif buffer_full:
			print_warning(tag, ("trace buffer filled up before "
				"tracing turned off, but won't consider this an "
				"error here; returning success"))
			success = True
			target_pids.append(build_pid)
		else:
			target_pids.append(build_pid)
			print_debug(tag, ("target_pids: {}").format(target_pids))
	else:
		print_error(tag, ("trace_on() or run_kernelbuild() returned "
			"failure; will just cleanup and return now. target_pids "
			"will be empty...").format())

	build_cleanup([build_stdout, build_stderr])
	now_cwd = unset_cwd(prev_cwd)
	if not now_cwd:
		print_error(tag, ("failed to cd back to {}").format(prev_cwd))
	print_debug(tag, ("returning target_pids: {}").format(target_pids))

	return target_pids

# First arg is "appname" member: used to construct output directory.
kernelbuild_app = app_to_run('kbuild', kernelbuild_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
