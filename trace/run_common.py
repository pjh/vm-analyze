# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# This file contains useful methods for both running applications and
# analyzing them later.

from conf.system_conf import *
from util.pjh_utils import *
import trace.vm_common as vm
import datetime
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time

targetpidsfile  = 'target_pids'
analysisdirname = 'generate-analysis'
PERFREPORT_DIRNAME = 'perf-reports'
RUN_OUTDIR  = "{}/measurement_results".format(scripts_dir)
latest_linkdir  = "{}/latest".format(RUN_OUTDIR)
proc_groups_fname = 'process_groups.tsv'
saved_vmas_fname = 'all_vmas.tsv'
specialerrorfile = 'ERROR'
PROCESS_GROUPS_NAME = 'process_groups'

##############################################################################

def determine_component(vma):
	tag = 'determine_component'

	# modstr contains the "stack" of modules that the call goes through
	# (with duplicates eliminated).
	modstr = vma.creator_module
	modlist = modstr.split(module_sep)
	fnstr = vma.creator_fn
	fnlist = fnstr.split(fn_sep)
	appname = vma.appname
	if appname in modstr:
		app_in_stack = True
	else:
		app_in_stack = False

	firefox_libs = ['libnspr4.so', 'libxul.so', ]

	# This is a big switch statement: component will be set to a specific
	# category / type, or set to the full fnstr for modules / functions
	# that we don't classify right now.
	# Order matters!!
	component = 'bug-if-this-string-appears-in-results'
	if libdl_re.search(modstr) or 'libc-2.17.so+do_dlopen' in fnstr:
		if app_in_stack:
			# Seen this from firefox: e.g.
			#   firefox+GetLibHandle->libdl-2.17.so+__dlopen->...
			#   libc-2.17.so+__GI___libc_dlopen_mode->...->
			#     libc-2.17.so+do_dlopen->ld-2.17.so+_dl_open->...
			component = 'Application_explicit_link'
		else:
			# Example: USRlibglib-2.0.so.0.3200.3+fn-lookup-error
			#   ->libc-2.17.so+__getpwnam_r->...->libc-2.17.so
			#   +__GI___libc_dlopen_mode->libc-2.17.so+dlerror_run
			#   ->ld-2.17.so+_dl_catch_error->libc-2.17.so+do_dlopen
			#   ->ld-2.17.so+_dl_open->ld-2.17.so+_dl_catch_error
			#   ->ld-2.17.so+dl_open_worker->ld-2.17.so+_dl_map_object
			#   ->ld-2.17.so+mmap64
			component = 'Other_explicit_link'
	elif lib_ld_re.search(modstr):
		if app_in_stack:
			#if libdl_re.search(modstr) or 'libc-2.17.so+do_dlopen' in fnstr:
			#	# Seen this from firefox: e.g.
			#	#   firefox+GetLibHandle->libdl-2.17.so+__dlopen->...
			#	#   libc-2.17.so+__GI___libc_dlopen_mode->...->
			#	#     libc-2.17.so+do_dlopen->ld-2.17.so+_dl_open->...
			#	component = 'Application_explicit_link'
			#else:
			print_error(tag, ("modstr={}, fnstr={}, appname={}").format(
				modstr, fnstr, appname))
			print_error(tag, ("unexpected: modstr {} contains "
				"ld-*.so and appname, but not libdl-*.so").format(
				modstr))
		elif (not (modlist[0] == 'USRld-2.15.so' or modlist[0] == 'ld-2.17.so')
				and (UNKNOWN_MODULE not in modlist)):
			# Haven't seen this yet... ok, did see it while analyzing
			# kernel-build trace.
			#   modstr unknown_module->USRlibc-2.15.so- >USRld-2.15.so
			#   modstr=USRlibnss_compat-2.15.so->USRlibc-2.15.so->USRld-2.15.so
			print_error(tag, ("modstr={}, fnstr={}, appname={}").format(
				modstr, fnstr, appname))
			print_error(tag, ("unexpected: modstr {} contains "
				"ld-*.so, but doesn't start with it and doesn't contain an "
				"explicit link operation").format(modstr))
		#else:
		#	component = 'Dynamic_linker'
		component = 'Dynamic_linker'
	elif '__GI___libc_malloc' in fnstr:
		# Full expected string: libc-2.17.so+__GI___libc_malloc
		if app_in_stack:
			component = 'Application_malloc()'
		else:
			component = 'Non-application_malloc()'
	elif '__GI___libc_realloc' in fnstr:
		# Full expected string: libc-2.17.so+__GI___libc_realloc
		if app_in_stack:
			component = 'Application_realloc()'
		else:
			component = 'Non-application_realloc()'
	elif '__GI___libc_free' in fnstr:
		# Full expected string:
		#   libc-2.17.so+__GI___libc_free->libc-2.17.so+munmap
		if app_in_stack:
			component = 'Application_free()'
		else:
			component = 'Non-application_free()'
	elif libc_re.search(fnlist[-1]) and 'mmap' in fnlist[-1]:
		# e.g. dedup+Encode->libc-2.17.so+mmap
		if len(fnlist) > 1 and appname in fnlist[-2]:
			component = 'Application_direct_mmap'
		# Don't use modlist, it is "coalesced"
		#elif len(modlist) > 1 and modlist[-2] in firefox_libs:
		elif (len(fnlist) > 1 and
				fnlist[-2].split(mod_fn_sep)[0] in firefox_libs):
			component = 'Firefox_lib_direct_mmap'
		else:
			component = fnstr
	elif libc_re.search(fnlist[-1]) and 'mprotect' in fnlist[-1]:
		# e.g. dedup+Encode->libc-2.17.so+mprotect
		if len(fnlist) > 1 and appname in fnlist[-2]:
			component = 'Application_direct_mprotect'
		elif (len(fnlist) > 1 and
				fnlist[-2].split(mod_fn_sep)[0] in firefox_libs):
			component = 'Firefox_lib_direct_mprotect'
		else:
			component = fnstr
	elif libc_re.search(fnlist[-1]) and 'munmap' in fnlist[-1]:
		if len(fnlist) > 1 and appname in fnlist[-2]:
			component = 'Application_direct_munmap'
		elif (len(fnlist) > 1 and
				fnlist[-2].split(mod_fn_sep)[0] in firefox_libs):
			component = 'Firefox_lib_direct_munmap'
		else:
			component = fnstr
	elif libc_re.search(fnlist[-1]) and 'syscall' in fnlist[-1]:
		if len(fnlist) > 1 and appname in fnlist[-2]:
			component = 'Application_direct_syscall'
		elif (len(fnlist) > 1 and
				fnlist[-2].split(mod_fn_sep)[0] in firefox_libs):
			component = 'Firefox_lib_direct_syscall'
		else:
			component = fnstr
	#elif libc_re.search(modstr) and not app_in_stack:
	#	# Important: app is not part of module stack, so this is libc
	#	# overhead that's not related to ld. e.g. this could be for program
	#	# setup and teardown, maybe pthread stuff...
	#	component = 'Libc overhead'
	else:
		component = modstr
		#component = fnstr

	#print_debug(tag, ("modstr={}, fnstr={}, appname={} -> component "
	#	"{}").format(modstr, fnstr, appname, component))

	return component

def determine_component_firefox(vma):
	tag = 'determine_component_firefox'

	# modstr contains the "stack" of modules that the call goes through
	# (with duplicates eliminated!).
	modstr = vma.creator_module
	modlist = modstr.split(module_sep)
	fnstr = vma.creator_fn
	fnlist = fnstr.split(fn_sep)
	appname = vma.appname
	if appname in modstr:
		app_in_stack = True
	else:
		app_in_stack = False

	rendering_keywords = ['View', 'Paint', 'Layout', 'Display', 'Render',
			'Layer', 'Image', ]

	keylist = []

	if libdl_re.search(modstr) or 'libc-2.17.so+do_dlopen' in fnstr:
		if app_in_stack:
			keylist.append('Application_explicit_link')
		else:
			keylist.append('Other_explicit_link')
	elif lib_ld_re.search(modstr):
		if app_in_stack:
			print_error(tag, ("modstr={}, fnstr={}, appname={}").format(
				modstr, fnstr, appname))
			print_error(tag, ("unexpected: modstr {} contains "
				"ld-*.so and appname, but not libdl-*.so").format(
				modstr))
		elif not (modlist[0] == 'USRld-2.15.so' or modlist[0] == 'ld-2.17.so'
				#or 'USR' in modlist[0]
				):
			# Haven't seen this yet...
			print_error(tag, ("modstr={}, fnstr={}, appname={}").format(
				modstr, fnstr, appname))
			print_error(tag, ("unexpected: modstr {} contains "
				"ld-*.so, but doesn't start with it and doesn't contain an "
				"explicit link operation").format(modstr))
		#else:
		#	keylist.append('Dynamic_linker')
		keylist.append('Dynamic_linker')
	else:
		if 'JS::' in fnstr or 'js::' in fnstr:
			keylist.append('javascript_fn')
		if 'GC' in fnstr:
			keylist.append('GC_fn')
		for keyword in rendering_keywords:
			if keyword in fnstr:
				keylist.append('rendering_keyword')
				break
		if 'plugin-container' in fnstr:
			keylist.append('plugin-container')
		if 'nsHostResolver' in fnstr:
			keylist.append('nsHostResolver')
		if 'dom' in fnstr or 'DOM' in fnstr:
			keylist.append('DOM')

	if len(keylist) == 0:
		#keylist.append('none_of_the_above')
		keylist.append(modstr)
		#keylist.append(fnstr)
	
	return keylist

# TODO: eventually, just use determine_component and eliminate this method...
def determine_component_plot(vma):
	tag = 'determine_component_plot'

	component = 'Unknown'

	modstr = vma.creator_module
	modlist = modstr.split(module_sep)
	creator_fn = vma.creator_fn
	#print_debug(tag, ("modstr={}, creator_fn={}").format(modstr, creator_fn))

	if lib_ld_re.search(modstr):
		component = 'Linker'
	elif 'libc_malloc' in creator_fn or 'alloc' in creator_fn:
		# App / library-level memory allocation?
		#   This isn't quite right yet because it will include pure-libc
		#   stacks that include calls to malloc - should also check for
		#   target process name here!!?!
		component = 'malloc'
	#elif 'libc-2.17.so' in modstr:
	#elif 'libc-' in modstr:
	elif ('libc-' in modstr and 
		not ('dedup' in modstr or 'firefox' in modstr or 'omp-csr' in modstr)):
		#print_debug(tag, ("libc modstr: {}").format(modstr))
		component = 'libc'
	elif (MODULE_KERNEL in modstr or 'teardown' in modstr):
		#print_error_exit(tag, ("need to investigate: why does all_cpus "
		#	"have kernel events, but not firefox or graph500??").format())
		component = 'OS'
	else:
		component = 'Application'
	
	return component

# Returns: the previous cwd on success, or None on error. The prev_cwd
# that is returned can/should later be passed to unset_cwd().
def set_cwd(new_cwd):
	tag = 'set_cwd'

	# http://docs.python.org/3/library/os.html?highlight=chdir#os.getcwd
	# http://docs.python.org/3/library/os.html?highlight=chdir#os.chdir
	prev_cwd = os.getcwd()
	try:
		os.chdir(new_cwd)
	except:
		print_error(tag, ("os.chdir({}) failed, returning error").format(
			new_cwd))
		return None
	if os.getcwd() != new_cwd:
		print_error(tag, ("os.getcwd() != {}, returning error").format(
			new_cwd))
		return None
	print_debug(tag, ("chdir into cwd {}").format(new_cwd))

	return prev_cwd

# Returns: the new cwd (the prev_cwd arg) on success, or None on error.
def unset_cwd(prev_cwd):
	tag = 'unset_cwd'

	try:
		os.chdir(prev_cwd)
	except:
		print_error(tag, ("os.chdir({}) failed, returning error").format(
			prev_cwd))
		return None
	if os.getcwd() != prev_cwd:
		print_error(tag, ("os.getcwd() != {}, returning error").format(
			prev_cwd))
		return None
	print_debug(tag, ("chdir back into cwd {}").format(prev_cwd))

	return prev_cwd

# Writes the pids in the target_pids list to a file (named by the
# global 'targetpidsfile' variable) in the outputdir. These pids can
# later be fetched using read_target_pids().
def write_target_pids(outputdir, target_pids):
	tag = 'write_target_pids'

	if not target_pids or type(target_pids) != list or len(target_pids) < 1:
		print_error(tag, ("invalid target_pids: {}").format(target_pids))
		return

	# Write the pids: one line per pid.
	fname = "{}/{}".format(outputdir, targetpidsfile)
	if os.path.exists(fname):
		print_unexpected(True, tag, ("target_pids file {} already "
			"exists!").format(fname))
	f = open(fname, 'w')

	count = 0
	for pid in target_pids:
		if type(pid) != int:
			print_error_exit(tag, ("invalid type {} for pid {}").format(
				type(pid), pid))
		f.write("{}".format(pid))
		count += 1
		if count < len(target_pids):
			f.write("\n")   # avoid final newline
	
	f.close()
	print_debug(tag, ("successfully wrote {} pids to {}").format(
		count, fname))

	return

# Writes a special file to the outputdir when an error occurred. The
# descr is written into the file, if specified.
def write_error_marker(outputdir, descr=None):
	tag = 'write_error_marker'

	fname = "{}/{}".format(outputdir, specialerrorfile)
	if os.path.exists(fname):
		print_unexpected(False, tag, ("specialerrorfile {} already "
			"exists!").format(fname))
	
	f = open(fname, 'w')
	if descr and len(descr) > 1:
		f.write("{}\n".format(descr))
	else:
		f.write('\n')
	f.close()

	return

# Looks for a target_pids file in the specified directory and if found,
# returns a list of the target pids in the file. If no file was found,
# an empty list is returned.
def read_target_pids(inputdir):
	tag = 'read_target_pids'

	fname = "{}/{}".format(inputdir, targetpidsfile)
	return read_target_pids2(fname)

def read_target_pids2(fname):
	tag = 'read_target_pids2'

	target_pids = []

	# We expect one pid per line.
	try:
		f = open(fname, 'r')
		line = f.readline()
		while line:
			if len(line) > 1 and line[0] != '#':
				pid = int(line)
				target_pids.append(pid)
			line = f.readline()
		f.close()
		print_debug(tag, ("got target_pids list from {}: {}").format(
			fname, target_pids))
	except IOError:
		print_debug(tag, ("didn't find target_pids file at {}, returning "
			"empty target pids list").format(fname))

	return target_pids

# Reads a pid from the first line of the specified file and returns
# it, or returns -1 on error.
# Note: this method executes a sudo shell command - don't pass uncontrolled
# input to it!
def read_pidfile(pidfile):
	tag = 'read_pidfile'

	retry_count = 2
	count = 0
	while True:
		# Unfortunately, the pid files may not be readable by the user
		# executing the script, so we use a sudo shell command to read
		# them.
		command = "sudo bash -c 'cat {} | head -n 1'".format(pidfile)
		p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
		pipe_out = None
		while pipe_out == None:
			(pipe_out, pipe_err) = p.communicate()
		pidline = pipe_out.decode('utf-8').strip()   # bytes to str
		retcode = p.wait()  # don't leave zombie processes!

		pid_re = re.compile(r"^(?P<pid>[0-9]+)")
		pidmatch = pid_re.match(pidline)
		if not pidmatch:
			# I unexpectedly hit this case once when trying to read
			# apache2's pidfile - add a retry loop?
			print_warning(tag, ("pidline {} didn't match expected pidfile "
				"format; {} retries left").format(pidline,
				retry_count - count))
			if count < retry_count:
				count += 1
				time.sleep(2)
				continue
			return -1
		break

	pid = int(pidmatch.group('pid'))
	print_debug(tag, ("extracted pid {} from pidfile {}").format(
		pid, pidfile))
	
	return pid

# Starts an "X virtual frame buffer" process. Redirects stdout and
# stderr to new files in the specified outputdir.
# Returns a tuple: (Popen object for the xvfb process, string to set
#   DISPLAY environment variable to to use the xvfb). On error returns
#   (None, None)
def start_xvfb(outputdir):
	tag = 'start_xvfb'

	# Check if there are already any 'Xvfb' processes running; if
	# there are, then attempt to kill them first, otherwise the
	# Xvfb startup will print an error:
	#   Fatal server error:
	#   Server is already active for display 99
	#       If this server is no longer running, remove /tmp/.X99-lock
	#       and start again.
	if not pgrep_pkill('Xvfb'):
		print_debug(tag, ("pgrep_pkill failed, returning error from "
			"here").format())
		return (None, None)

	xvfb_bin = '/usr/bin/Xvfb'
	xvfb_display = ':99'
	xvfb_opts = '-ac -screen 0 1280x1024x24'
	  # -ac: disable access control
	  # Other options are pretty standard; see Xvfb(1) and Xserver(1)
	(xvfb_stdout, xvfb_stderr) = new_out_err_files(outputdir, 'xvfb')
	    # BUG: these files are never closed?
	
	cmdline = ("{} {} {}").format(xvfb_bin, xvfb_display, xvfb_opts)
	args = shlex.split(cmdline)
	print_debug(tag, ("executing args={} as a child process").format(args))
	xvfb_p = subprocess.Popen(args, stdout=xvfb_stdout, stderr=xvfb_stderr)
	if not xvfb_p:
		print_error(tag, ("subprocess.Popen returned None; cmdline="
			"{}").format(cmdline))
		return (None, None)
	if xvfb_p.returncode:
		print_error(tag, ("xvfb_p has terminated already with code "
			"{} - check stderr file").format(xvfb_p.returncode))
		return (None, None)

	print_debug(tag, ("Xvfb process started successfully, pid is "
		"{}").format(xvfb_p.pid))
	return (xvfb_p, xvfb_display)

# Terminates the xvfb_p process returned in [0] of start_xvfb().
def stop_xvfb(xvfb_p):
	tag = 'stop_xvfb'

	if not xvfb_p:
		return

	#stopsig = signal.SIGTERM
	stopsig = signal.SIGINT   # (Ctrl-c)
	print_debug(tag, ("sending signal {} to Xvfb process with pid "
		"{}").format(stopsig, xvfb_p.pid))
	xvfb_p.send_signal(stopsig)

	print_debug(tag, ("waiting indefinitely for Xvfb process to "
		"exit").format())
	retcode = xvfb_p.wait()
	print_debug(tag, ("got retcode {} from Xvfb process").format(
		retcode))
	
	return

def proc_group_to_str(proc_group):
	return str(list(map(lambda proc: proc.name(), proc_group)))

# Writes the proc_groups data structure to a special file in the
# outputdir. proc_groups is a nested list: each sublist in the
# list contains the processes that should be grouped together, with
# the first entry in the sublist considered the head/main process.
# The expected format of an entry in the list is 'omp-csr-20671'.
# 
# If the file already exists, it will be overwritten.
# The proc_groups can be reconstructed by calling read_process_groups().
# 
# Returns: True on success, False on error.
def write_process_groups(outputdir, proc_groups):
	tag = 'write_process_groups'

	fname = "{}/{}".format(outputdir, PROCESS_GROUPS_NAME)
	if os.path.exists(fname):
		print_debug(tag, ("process_groups file {} already exists, "
			"(e.g. due to repeated run_queries() calls), we'll "
			"just overwrite it").format(fname))

	f = open(fname, 'w')
	if not f:
		print_error_exit(tag, ("failed to open {} for writing").format(
			fname))
		return False
	
	count = 0
	for proc_group in proc_groups:
		count += len(proc_group)
	f.write("{} processes in {} groups:\n".format(
		count, len(proc_groups)))
	for proc_group in proc_groups:
		f.write("{}\n".format(proc_group_to_str(proc_group)))

	f.close()
	return True

pg_process_re = re.compile(r'(?P<task>[\w\-<>. \#~/:+]+)-(?P<pid>\d+)')
  # Used for process groups stuff.
  # see trace_event_re - some weird characters in task names...

# Reconstructs a process_groups data structure written out by
# write_process_groups. The caller can set either or both of
# include_task and include_pid to get back a structure that includes
# just the task name, just the pids, or both. If just the pids are
# returned, they will be ints rather than strings.
# Returns: a process_groups data structure, or None on error.
def read_process_groups(inputdir, include_task=True, include_pid=True):
	tag = 'read_process_groups'

	if not include_task and not include_pid:
		print_error(tag, ("both include_task and include_pid are False"))
		return None

	fname = "{}/{}".format(inputdir, PROCESS_GROUPS_NAME)
	try:
		f = open(fname, 'r')
	except FileNotFoundError:
		print_error(tag, ("process_groups file {} not found").format(
			fname))
		return None

	header = f.readline()
	print_debug(tag, ("ignoring header line: {}").format(header))

	process_groups = []
	while True:
		line = f.readline()
		if not line:
			break

		processes = pg_process_re.findall(line)
		
		group = []
		for p in processes:
			if include_task and include_pid:
				s = "{}-{}".format(p[0], p[1])
			elif include_task:
				s = p[0].strip()
			else:
				s = int(p[1])
			group.append(s)
		if len(group) > 0:
			process_groups.append(group)
		else:
			print_warning(tag, ("empty group from line {}").format(
				line))
	
	print_debug(tag, ("constructed process_groups structure: "
		"{}").format(process_groups))

	return process_groups

# Searches through the process_groups data structure and returns the
# pid of the head/leader process for the group the pid is found in.
# pid must be an int.
# Returns just the pid (not the string), or None if not found.
def process_groups_leader(process_groups, pid):
	tag = 'process_groups_leader'

	# This method assumes that the search pid is only found in a single
	# group; if this were not true, it would mean that the process_groups
	# structure is corrupted.
	# Remember that the entries in the process_groups sublists could be
	# something like "apache-1234" or just "1234".

	for group in process_groups:
		for p in group:
			if type(p) is int and p == pid:
				return group[0]
			elif type(p) is str and str(pid) in p:
				pg_match = pg_process_re.match(group[0])
				if pg_match:
					return int(pg_match.group('pid'))
				else:
					print_warning(tag, ("found pid as substring, but "
						"regex match failed - bad format in groups? "
						"pid={}, p={}, group[0]={}").format(
						pid, p, group[0]))
					return None

	return None

# Searches for a window matching the specified title. env may be none,
# or it may be an environment with a specific DISPLAY value set.
# Currently, if more than one window matches the search term, just
# the first handle is returned (todo: update this method to return
# a list of all handles).
# 
# Note that this method executes a shell subprocess, which is a security
# hazard for uncontrolled input.
#
# Returns: an *int* representing the X window handle for the specified
# search title. If no X window was found, -1 is returned. None is
# returned on error.
def xdotool_get_window_handle(title, env=None):
	tag = 'xdotool_get_window_handle'

	# Expected output from this command: one line of stdout that contains
	# the numerical X window handle that we care about, one line of stderr
	# that we don't care about (since we don't care about it, it will
	# be printed when run_apps.py runs: look for "Defaulting to search
	# window name, class, and classname").
	# What happens if there is NO output? The out_line will be empty,
	# so the regex match will fail.
	cmd = "xdotool search \"{}\"".format(title)
	print_debug(tag, ("constructed cmd=\"{}\"").format(cmd))
	retries = 2
	retrytime = 5
	while retries >= 0:
		(retcode, out, err) = exec_cmd_get_output(cmd, env)
		print_debug(tag, ("got retcode={}, out={}").format(
			retcode, out))
		handle_re = re.compile(r"^(?P<handle>[0-9]+)")
		handlematch = handle_re.match(out)  # get first match...
		if handlematch:
			break
		print_warning(tag, ("failed to get handle from output {} "
			"(err={}), will wait {} seconds and retry").format(
			out, err, retrytime))
		retries -= 1
		if retries >= 0:
			time.sleep(retrytime)

	if not handlematch:
		# This is the not-found case, not an error.
		print_error(tag, ("failed to get X window handle after {} "
			"tries, returning not-found").format(retries+1))
		return -1

	handle = int(handlematch.group('handle'))
	print_debug(tag, ("xdotool got X window handle {} for office "
		"app").format(handle))

	return handle

# Opens two new files for writing stdout and stderr output to, in the
# specified directory with the specified prefix (i.e. appname). The
# returned files should be .close()d when done writing to them.
# 
# Returns a tuple: (stdout file, stderr file). Returns (None, None) on
# error.
def new_out_err_files(outputdir, prefix):
	tag = 'new_out_err_files'

	stdout_fname  = "{}/{}-stdout".format(outputdir, prefix)
	stderr_fname  = "{}/{}-stderr".format(outputdir, prefix)
	try:
		stdout  = open(stdout_fname, 'w')
		stderr  = open(stderr_fname, 'w')
	except:
		print_error(tag, ("caught exception from open('w') for "
			"{} or {}").format(stdout_fname, stderr_fname))
		return (None, None)

	return (stdout, stderr)

def stdout_stderr_init(outputdir, prefix):
	tag = 'stdout_stderr_init'

	stdout_fname  = "{}/{}-stdout".format(outputdir, prefix)
	stderr_fname  = "{}/{}-stderr".format(outputdir, prefix)
	stdout  = open(stdout_fname, 'w')
	stderr  = open(stderr_fname, 'w')

	return (stdout, stderr)

def signal_handler_nop(signum, stackframe):
	tag = 'signal_handler_nop'
	#print_debug(tag, ("received signum {}, just returning now").format(
	#	signum))
	return

##############################################################################

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)
