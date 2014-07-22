# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Directory locations that may change depending on the system that we're
# running on:

system = 'stjohns'

home_dir		= '/scratch/pjh'   # must be absolute!
PERF_DIR		= "{}/bin".format(home_dir)
repos_dir		= "{}".format(home_dir)
scripts_dir		= "{}/vm-analyze".format(repos_dir)
conf_dir		= "{}/conf".format(scripts_dir)
apps_dir		= "{}/vmstudy-apps".format(repos_dir)
data_dir		= "{}/vmstudy-data".format(repos_dir)
LTRACE_DIR		= "{}/ltrace_outfiles".format(data_dir)
appscripts_dir	= "{}/app_scripts".format(scripts_dir)

trace_user = 'pjh'
trace_group = 'grad_cs'
  # After the trace is complete, the owner:group of the tracefilename
  # output file will be set using these. Also applies to perf files.

# stjohns: Intel(R) Xeon(R) CPU L5640  @ 2.27GHz
#   http://ark.intel.com/products/47926
#   https://en.wikipedia.org/wiki/List_of_Intel_Xeon_microprocessors#.22Westmere-EP.22_.2832_nm.29_Efficient_Performance
#   According to /sys/devices/system/cpu/cpu0/cache/index0/shared_cpu_list,
#   stjohns has 12 cores with 2 hyperthreads per core (hyperthreads share
#   level-1 caches, it seems); private L1 + L2 caches per core (shared
#   amongst the two hyperthreads), and two L3 caches shared by 6
#   cores (12 threads) each.
# I ran some small graph500 benchmarks (omp-csr/omp-csr -V -s 18)
# with tracing on, and found that the trace infrastructure has one
# buffer PER-HARDWARE-THREAD, not per-core! So on stjohns, the trace
# lines come from cores 000 up to 023. This is somewhat unfortunate,
# as it means that in order to increase the per-thread buffer size,
# we end up using twice as much total memory. SOLUTION: use the
# max_cpus=n kernel boot argument to limit the number of CPUs to
# just 4! Otherwise, we need to use half of the system's memory
# just to get 500 MB trace buffers per hw thread. With max_cpus set,
# I verified that the kernel trace infrastructure only uses (and
# presumably only allocates trace buffer memory for) four cores.
memtotal = 24676440   # kB
num_cores = 4
num_hw_threads = 4
#suggested_tracebuf_size_kb = 1048576  # 1 GB
suggested_tracebuf_size_kb = 1572864  # 1.5 GB
#suggested_tracebuf_size_kb = 2097152  # 2 GB
  # 2 GB memory per-core still leaves 23.5 - 8 = 15.5 GB memory
  # for application use. However, the kernel may complain when
  # we try to set this as the buffer_size_kb for tracing: 
  #   "bash: echo: write error: Cannot allocate memory"
  # Possible solution: set this as the trace_buf_size at boot
  # time using boot parameter?!?
'''
num_cores = 12
num_hw_threads = 24
suggested_tracebuf_size_kb = int((memtotal / num_hw_threads) / 2)
  # 50% of per-hw-thread memory: 23.5 GB memory -> 1004 MB per hw
  # thread -> 502 MB trace buffer per thread. I'd like to have more
  # memory per thread to avoid the trace buffer overflowing, but
  # for now this is probably as much as we're going to reasonably
  # get; now just 11.75 GB is left for application use :-/
'''

libreoffice_bin = '/usr/lib/libreoffice/program/soffice.bin'
  # Use soffice.bin directly, rather than the symlinks and wrapper scripts
  # around it.

oldrepo_dir     = "{}/virtual-uw".format(repos_dir)
glibc_dir		= '/noexist'
gcc_dir			= '/noexist'

# These are used for determining whether or not files should count
# as shared library files.  If these directories don't actually exist
# on some system, shouldn't be a problem.
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

