# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Directory locations that may change depending on the system that we're
# running on:

system = 'verbena'

home_dir		= '/home/pjh'   # must be absolute!
PERF_DIR		= "{}/bin".format(home_dir)
repos_dir       = "{}/research".format(home_dir)
scripts_dir		= "{}/vm-analyze".format(repos_dir)
conf_dir        = "{}/conf".format(scripts_dir)
apps_dir		= "{}/vmstudy-apps".format(repos_dir)
data_dir        = "{}/vmstudy-data".format(repos_dir)
LTRACE_DIR      = "{}/ltrace_outfiles".format(data_dir)
appscripts_dir	= "{}/app_scripts".format(scripts_dir)

suggested_tracebuf_size_kb = 512 * 1024
num_hw_threads = 2

trace_user = 'pjh'
trace_group = 'pjh'
  # After the trace is complete, the owner:group of the tracefilename
  # output file will be set using these. Also applies to perf files.

libreoffice_bin = '/usr/lib/libreoffice/program/soffice.bin'
  # Use soffice.bin directly, rather than the symlinks and wrapper scripts
  # around it.

oldrepo_dir     = "{}/virtual-uw".format(repos_dir)
glibc_dir		= "{}/glibc-testinstall/lib".format(oldrepo_dir)
gcc_dir			= "{}/gcc-testinstall/lib64".format(oldrepo_dir)

# These are used for determining whether or not files should count
# as shared library files.
# NOTE: using /usr/lib here may be more "permissive" than we eventually
# want - "application-specific" libraries used specifically for apache,
# php, etc. will be included as "shared libraries"!
#SHARED_LIB_DIRS = ['/usr/lib/x86_64-linux-gnu', '/lib/x86_64-linux-gnu']
SHARED_LIB_DIRS = [
		'/lib/x86_64-linux-gnu',
		'/usr/lib/x86_64-linux-gnu',
		'/usr/lib', # /mozilla, /firefox, /jvm, /libreoffice, /ure, /python3.3
		'/opt/google/chrome',
	]
# Ugh: on my system, 'glibc-testinstall' is a symlink, but in the maps
# file output (and hence my vma filename), the symlink becomes the true
# directory. This is really extremely super annoying.
possible_glibc_dirs = [
		"{}/glibc-testinstall/lib".format(oldrepo_dir),
		"{}/glibc-testinstall-first/lib".format(oldrepo_dir),
		"{}/glibc-testinstall-notailcalls/lib".format(oldrepo_dir)
	]
possible_gcc_dirs = [
		"{}/gcc-testinstall/lib64".format(oldrepo_dir),
		"{}/gcc-testinstall-first/lib64".format(oldrepo_dir),
		"{}/gcc-testinstall-notailcalls/lib64".format(oldrepo_dir)
	]
SHARED_LIB_DIRS += possible_glibc_dirs
SHARED_LIB_DIRS += possible_gcc_dirs

USR_SHARE_DIRS = ['/usr/share']

# envfile may need to be sourced before executing applications, e.g. to
# set the LD_LIBRARY_PATH and LD_RUN_PATH to point to the correct glibc
# etc...
#   Not sure if there's an easy way to source this for subprocesses;
#   instead, just define "env" map here. Todo: parse envfile to generate
#   env map at runtime?
#envfile = "{}/mylibs_runtime.source".format(app_dir)
lib_dirs = "{}:{}:/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu".format(
		glibc_dir, gcc_dir)
newlibs_envmap = {    # envmap = {
		'LD_LIBRARY_PATH' : lib_dirs,
		'LD_RUN_PATH'     : lib_dirs,
		}

sys_debug_dir   = '/sys/kernel/debug'   # could differ on other systems

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)

