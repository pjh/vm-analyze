# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Memcached application script. The memcached "client" that's currently
# used comes from the CloudSuite Data Caching benchmark:
#   http://parsa.epfl.ch/cloudsuite/memcached.html
# 
# Build + setup instructions: do these once / occasionally by hand, not
# done automatically by this script.
#   Create the scaled dataset using a command like this in the CloudSuite
#   directory:
#     ./loader -a ../twitter_dataset/twitter_dataset_unscaled
#         -o ../twitter_dataset/twitter_dataset_3x -s servers.txt
#         -w 1 -S 3 -D 1024 -j -T 1 -r 30000
#
# Note: this script uses timeout features that were added to Python 3.3
# (available in Ubuntu 13.04) - if this is a problem, they should be
# fairly easy to eliminate from the code, just search for "timeout".

from app_scripts.app_browser import *
from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo
from util.pjh_utils import *
import signal

MC_POOLSIZE_MB = 1024
#MC_POOLSIZE_MB = 10240
  # size of memcached "buffer pool" in MB. Make sure that the client
  # dataset file specified below matches the buffer pool size (it's
  # probably ok if the dataset is too large, as values will just be
  # evicted, but if it's too small, then the entire memcached pool
  # won't be used...).

# Workload:
NUM_WORKER_THREADS = 4
GETPUT_RUNTIME = 20
GETPUT_PERCENTAGE = 0.8

WHICHCLIENT = 'cloudsuite'
  # client choices: 'cloudsuite', ...

MC_BIN = "/usr/bin/memcached"
#MC_PIDFILE = '/var/run/memcached.pid'
MC_APPNAME = 'mcache'

HOSTNAME = 'localhost'
MC_PORT    = 11211        # 11223
  # this script is now used by app_LAMP.py as well, and mediawiki setup
  # expect memcached to be running on default port, 11211.

CLOUDSUITE_CLIENT_DIR = ("{}/cloudsuite/memcached-bench").format(apps_dir)
CLOUDSUITE_CLIENT_BIN = ("{}/memcached_client/loader").format(
		CLOUDSUITE_CLIENT_DIR)
CLOUDSUITE_CLIENT_DATASET = ("{}/twitter_dataset/"
		"twitter_dataset_3x").format(CLOUDSUITE_CLIENT_DIR)
		#"twitter_dataset_30x").format(CLOUDSUITE_CLIENT_DIR)

#POLL_PERIOD = 0
POLL_PERIOD = 10

##############################################################################

# ...
# Returns a tuple: (success, memcached server Popen object)
def start_mc_server(mc_stdout, mc_stderr):
	tag = 'start_mc_server'

	# Check that the default memcached service from Ubuntu or any other
	# memcached server is not already running in the background on MC_PORT:
	if not pgrep_pkill('memcached', 2):
		print_error(tag, ("pgrep_pkill() failed, returning error "
			"now").format())
		return (False, None)

	# Options used so far:
	#   -t: number of memcached threads (don't increase beyond 4 - memcached
	#       has thread scalability issues, apparently)
	#   -m: maximum amount of memory memcached will use for storing
	#       keys + values
	#   -n: minimum size for key+value+flags items (default is 48; the
	#       value is recommended by CloudSuite).
	mc_cmd = ("{} -t 4 -m {} -n 550 -p {}").format(
			MC_BIN, MC_POOLSIZE_MB, MC_PORT)
	args = shlex.split(mc_cmd)
	print_debug(tag, ("executing args={} as a child process").format(args))
	mc_p = subprocess.Popen(args, stdout=mc_stdout, stderr=mc_stderr)
	if not mc_p:
		print_error(tag, ("subprocess.Popen returned None; cmdline="
			"{}").format(mc_cmd))
		return (False, None)
	if mc_p.returncode:
		print_error(tag, ("mc_p has terminated already with code "
			"{} - check {}").format(mc_p.returncode, mc_stderr.name))
		return (False, None)

	print_debug(tag, ("started memcached server with pid {}").format(
		mc_p.pid))

	return (True, mc_p)

def stop_mc_server(mc_p):
	tag = 'stop_mc_server'

	# Since we started the memcached server as the current user, we
	# should be allowed to kill the server with a simple signal
	# as the current user. Ctrl-C works for memcached.
	stopsig = signal.SIGINT
	mc_p.send_signal(stopsig)
	try:
		returncode = mc_p.wait(timeout=10)
	except subprocess.TimeoutExpired:
		print_error(tag, ("memcached server didn't terminate "
			"after SIGINT, will try sudo SIGKILL but won't wait()"))
		cmdline = ("sudo bash -c 'kill -SIGKILL {}'").format(
				mc_p.pid)
		args = shlex.split(cmdline)
		subprocess.call(args)
		return False

	print_debug(tag, ("successfully killed memcached server, "
		"returncode was {}").format(returncode))
	return True

# Starts the memcached client. Depending on the client, all of the
# work may be done in this method (the client will start, run to completion,
# and stop all right here), so we won't return a Popen object.
#
# Returns a tuple: (success, Popen object for client).
def start_mc_client(client_stdout, client_stderr, tracer, serverpid,
		phase, outputdir):
	tag = 'start_mc_client'

	servers_fname = ("{}/servers-{}.txt").format(outputdir, MC_PORT)

	if WHICHCLIENT is 'cloudsuite':
		# http://parsa.epfl.ch/cloudsuite/memcached.html
		print_debug(tag, ("Executing phase '{}' with cloudsuite "
			"loader").format(phase))

		if phase == 'load':
			# Set up servers.txt first:
			servers_line = "{}, {}".format(HOSTNAME, MC_PORT)
			lines = [servers_line]
			write_conf_file(lines, servers_fname, overwrite=True)
			print_debug(tag, ("wrote servers.txt file at {}").format(
				servers_fname))

			# For now, this command just "preloads" the data (-j): a single
			# worker thread (-w 1) loads the entire dataset file (which
			# should have already been scaled up to the appropriate size)
			# into the memcached server, at the specified request rate (-r).
			# -T controls the rate that stats will be printed into the
			# stdout file. -S 1 (scale factor) is necessary, or else the
			# loader will segfault.
			# I've found that a requests per second rate of 30000 is
			# reasonable: a 900 MB dataset (twitter dataset x3) loads in
			# about 30 seconds, with no requests delayed. Don't use
			# more than 1 worker, or the load phase will actually be
			# much much slower (even with a modest number of workers,
			# like 4!).
			client_cmd = ("{} -a {} -s {} -w {} -D {} -j -T 1 -S 1 -r "
				"30000").format(
				CLOUDSUITE_CLIENT_BIN, CLOUDSUITE_CLIENT_DATASET,
				servers_fname, 1, MC_POOLSIZE_MB)
		elif phase == 'getput':
			# In second phase (must happen after load phase), perform
			# an actual get-put workload:
			#   -w: number of worker threads
			#   -T: stats print interval
			#   -c: number of TCP connections (from each worker, I think)
			#   -g: percentage of gets to perform (0.8 -> 80% gets)
			#   -e: exponential arrival distribution (vs. constant;
			#       CloudSuite recommends -e for this phase).
			#   -t: length of time to run
			#   -r: request rate; for 80% gets from 1 worker with 25
			#       connections, server on verbena seemed to be able
			#       to handle 25000 requests/second without any queuing
			#       up and a 95th-%ile response time less than 20 ms
			#       (which doesn't quite meet the 10ms CloudSuite
			#       guidelines, but whatever)
			client_cmd = ("{} -a {} -s {} -w {} -T 1 -c 10 -g {} "
				"-t {} -e -r 25000").format(
				CLOUDSUITE_CLIENT_BIN, CLOUDSUITE_CLIENT_DATASET,
				servers_fname, NUM_WORKER_THREADS, GETPUT_PERCENTAGE,
				GETPUT_RUNTIME)
		else:
			print_error(tag, ("invalid cloudsuite phase {}").format(
				phase))
			return (False, None)
	else:
		print_error(tag, ("invalid client {}").format(WHICHCLIENT))
		return (False, None)

	args = shlex.split(client_cmd)
	print_debug(tag, ("executing args={} as a child process").format(args))
	client_p = subprocess.Popen(args, stdout=client_stdout,
			stderr=client_stderr)
	if not client_p:
		print_error(tag, ("subprocess.Popen returned None; cmdline="
			"{}").format(client_cmd))
		return (False, None)
	clientpid = client_p.pid

	if WHICHCLIENT == 'cloudsuite':
		# For cloudsuite, wait for the loader to run to completion,
		# then return None for the client_p.
		retcode = tracer.trace_wait(client_p, POLL_PERIOD, WHICHCLIENT,
				targetpid=serverpid)
		if retcode == 'error' or retcode == 'full':
			# Do we expect trace buffer to fill up during this
			# application? For now, start by treating this as
			# an error.
			#   Loading 3x scaled dataset file (~900 MB) into 1024 MB
			#   memcached instance: takes about 30 seconds, produces
			#   a 152 MB trace-events-full file with no truncation.
			print_error(tag, ("trace_wait() returned {}; client's "
				"returncode is {}. Will terminate processes and "
				"return error here").format(retcode, client_p.returncode))
			kill_Popens([client_p])
			return (False, None)
		elif client_p.returncode is None:
			print_error(tag, ("client process' returncode not "
				"set?!?").format())
			kill_Popens([client_p])
			return (False, None)
		elif client_p.returncode != 0:
			print_error(tag, ("client process returned error {}").format(
				client_p.returncode))
			return (False, None)

		print_debug(tag, ("cloudsuite loader successfully ran to "
			"completion, returning None for client_p").format())
		client_p = None

	else:
		if client_p.returncode:
			print_error(tag, ("client_p has terminated already with code "
				"{} - check {}").format(client_p.returncode,
				client_stderr.name))
			return (False, None)

	print_debug(tag, ("started memcached client with pid {}").format(
		clientpid))

	return (True, client_p)

# Runs the memcached client that may have already been started by
# start_mc_client() (client_p argument should be non-None then).
# If the client ran entirely in start_mc_client(), then client_p
# may be None and this method will be a nop.
# Returns True on success or False on error.
def run_mc_client(client_p, tracer):
	tag = 'run_mc_client'

	if WHICHCLIENT is 'cloudsuite':
		# For now, cloudsuite client runs entirely during the
		# start_mc_client() method.
		if client_p:
			# This may change later...
			print_error(tag, ("unexpected: client is {}, but we "
				"don't have any work for client_p {} to do").format(
				WHICHCLIENT, client_p))
			return False
		else:
			print_debug(tag, ("nothing to do here").format())
	else:
		print_error(tag, ("unexpected client {}").format(WHICHCLIENT))
		return False

	return True

def stop_mc_client(client_p):
	tag = 'stop_mc_client'

	if WHICHCLIENT is 'cloudsuite':
		# For now, cloudsuite client runs entirely during the
		# start_mc_client() method.
		if client_p:
			# This may change later...
			print_error(tag, ("unexpected: client is {}, but we "
				"don't have any work to do to stop client_p {}").format(
				WHICHCLIENT, client_p))
			return False
		else:
			print_debug(tag, ("nothing to do here").format())
	else:
		print_error(tag, ("unexpected client {}").format(WHICHCLIENT))
		return False

	return True

# Executes memcached...
#
# Returns: a target_pids list containing the top-level pid of the
# memcached app, or an empty list on error.
def memcached_exec(outputdir):
	tag = 'memcached_exec'

	target_pids = []
	tracer = traceinfo(MC_APPNAME)
	(mc_stdout, mc_stderr) = new_out_err_files(outputdir, MC_APPNAME)
	(client_stdout, client_stderr) = new_out_err_files(outputdir,
			WHICHCLIENT)

	success = tracer.trace_on(outputdir, descr=("starting memcached "
		"server").format())
	if not success:
		print_error(tag, ("trace_on failed, returning now"))
		close_files([mc_stdout, mc_stderr, client_stdout, client_stderr])
		return []

	(success, mc_p) = start_mc_server(mc_stdout, mc_stderr)
	if not success or not mc_p:
		print_error(tag, ("start_mc_server failed ({}, {}), returning "
			"now").format(success, mc_p))
		close_files([mc_stdout, mc_stderr, client_stdout, client_stderr])
		return []

	mc_server_pid = mc_p.pid
	target_pids.append(mc_server_pid)

	# Start the memcached client: note that for some clients, the
	# client runs entirely in this method, so success may be returned
	# but client_p may be None.
	(success, client_p) = start_mc_client(client_stdout, client_stderr,
			tracer, mc_p.pid, 'load', outputdir)
	if not success:
		print_error(tag, ("start_mc_client failed ({}, {}), stopping "
			"memcached server and returning. echo {} > target_pids "
			"if you still want to analyze this trace").format(
			success, client_p, mc_p.pid))
		client_p = None
		target_pids = []
	
	use_getput_phase = True
	if success and use_getput_phase:
		tracer.trace_checkpoint('getput start')
		(success, client_p) = start_mc_client(client_stdout, client_stderr,
				tracer, mc_p.pid, 'getput', outputdir)
		if not success:
			print_error(tag, ("start_mc_client failed ({}, {}), stopping "
				"memcached server and returning").format(success, client_p))
			stop_mc_server(mc_p)
			close_files([mc_stdout, mc_stderr, client_stdout, client_stderr])
			return []
	elif success:
		success = run_mc_client(client_p, tracer, mc)
		if not success:
			print_error(tag, "run_mc_client failed")
			target_pids = []

	if client_p:
		stop_mc_client(client_p)
	stop_mc_server(mc_p)

	(tracesuccess, buffer_full) = tracer.trace_off(
			"stopping memcached server")
	if not tracesuccess or buffer_full:
		print_error(tag, ("trace buffer filled up before "
			"tracing turned off - considering this an error "
			"here. echo {} > target_pids to analyze anyway").format(
			mc_server_pid))
		success = False
		target_pids = []
	close_files([mc_stdout, mc_stderr, client_stdout, client_stderr])

	print_debug(tag, ("returning target_pids={}").format(target_pids))
	
	return target_pids

# First arg is "appname" member: used to construct output directory.
memcached_app = app_to_run(MC_APPNAME, memcached_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
