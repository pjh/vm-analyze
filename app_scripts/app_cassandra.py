# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Cassandra, exercised using YCSB.
# 
# Cassandra is a java application; it runs in a single process with many
# (e.g. 30+) threads. Its command line looks like this:
#   java -ea -javaagent:/home/pjh/research/virtual/apps/cassandra/bin/../lib/jamm-0.2.5.jar -XX:+UseThreadPriorities -XX:ThreadPriorityPolicy=42 -Xms1024M -Xmx1024M -Xmn200M -XX:+HeapDumpOnOutOfMemoryError -Xss180k -XX:+UseParNewGC -XX:+UseConcMarkSweepGC -XX:+CMSParallelRemarkEnabled -XX:SurvivorRatio=8 -XX:MaxTenuringThreshold=1 -XX:CMSInitiatingOccupancyFraction=75 -XX:+UseCMSInitiatingOccupancyOnly -XX:+UseTLAB -XX:+UseCondCardMark -Djava.net.preferIPv4Stack=true -Dcom.sun.management.jmxremote.port=7199 -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.authenticate=false -Dlog4j.configuration=log4j-server.properties -Dlog4j.defaultInitOverride=true -Dcassandra-pidfile=/home/pjh/research/virtual/measure/measurement_results/20130812-15.06.12/cassandra/target_pid -Dcassandra-foreground=yes -cp /home/pjh/research/virtual/apps/cassandra/bin/../conf:/home/pjh/research/virtual/apps/cassandra/bin/../build/classes/main:/home/pjh/research/virtual/apps/cassandra/bin/../build/classes/thrift:/home/pjh/research/virtual/apps/cassandra/bin/../lib/antlr-3.2.jar: ...[many more .jars]... :/home/pjh/research/virtual/apps/cassandra/bin/../lib/thrift-server-0.2.1.jar org.apache.cassandra.service.CassandraDaemon
# Most of these arguments are set in the conf file conf/cassandra-env.sh.
#   -ea: enable assertions (in ALL classes)
#   -javaagent: loads Java programming language agent
#     http://docs.oracle.com/javase/7/docs/api/java/lang/instru
#     ment/package-summary.html
#   -XX:+UseThreadPriorities: non-std option; ...?
#   -XX:ThreadPriorityPolicy=42: non-std option; ...?
#   -Xms1024M: initial Java heap size! - 1 GB
#   -Xmx1024M: max Java heap size! - 1 GB
#   -Xmn200M: min heap size? Or "size of the younger generation"?
#   -XX:+HeapDumpOnOutOfMemoryError: 
#   -Xss180k: thread stack size!
#   -XX:+UseParNewGC: 
#   -XX:+UseConcMarkSweepGC: enables CMS instead of G1
#   -XX:+CMSParallelRemarkEnabled: 
#   -XX:SurvivorRatio=8: 
#   -XX:MaxTenuringThreshold=1: 
#   -XX:CMSInitiatingOccupancyFraction=75: 
#   -XX:+UseCMSInitiatingOccupancyOnly: 
#   -XX:+UseTLAB: TLAB == "thread local allocation buffers"
#   -XX:+UseCondCardMark: 
#   -Djava.net.preferIPv4Stack=true: sets system property value
#   -cp: classpath
#   org.apache.cassandra.service.CassandraDaemon: class that contains main.

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo
import time

cass_dir           = "{}/cassandra".format(apps_dir)
ycsb_dir           = "{}/ycsb".format(apps_dir)
cass_data_dir      = "/var/lib/cassandra"
cass_bin           = "{}/bin/cassandra".format(cass_dir)
cqlsh_bin          = "{}/bin/cqlsh".format(cass_dir)
ycsb_bin           = "{}/bin/ycsb".format(ycsb_dir)
ycsb_dbname        = 'cassandra-10'
  # See the set of DATABASES in ycsb/bin/ycsb and by running
  # ycsb/bin/ycsb -h. Earlier I had added a "cassandra-200" client
  # that was pretty much the same as cassandra-10 (I change the number
  # of retries apparently) and then re-built ycsb, but I'm not sure
  # that is/was necessary. Stick with vanilla ycsb and the most recent
  # cassandra client.
cass_startuptime   = 12   # 12 seems to suffice...

##############################################################################
# YCSB #
########

# Returns: ycsb-params filename on success, or None on error.
def ycsb_load(output_dir, ycsb_stdout, ycsb_stderr):
	tag = 'ycsb_load'
	global ycsb_bin, ycsb_dbname

	# May want to tweak these later; defaults that are currently not
	# specified explicitly here are:
	#   Default data size: 1 KB records (10 fields, 100 bytes each, plus
	#     24-byte key)
	ycsb_recordcount = '100000'  # num keys to insert (each with 10 fields)
	ycsb_opcount = '100000'  # total num. operations
	ycsb_readprop = '0.5'
	ycsb_updateprop = '0.5'
	ycsb_scanprop = '0'
	ycsb_insertprop = '0'
	ycsb_distribution = 'uniform'   # 'uniform', 'zipfian', or 'latest'

	ycsb_params_fname = "{}/ycsb-params".format(output_dir)
	ycsb_params = []
	ycsb_params.append(("# YCSB parameters used by app_cassandra.py"))
	ycsb_params.append(("hosts=localhost"))  #xxx: support for non-localhost?
	ycsb_params.append(("recordcount={}").format(ycsb_recordcount))
	ycsb_params.append(("operationcount={}").format(ycsb_opcount))
	ycsb_params.append(("workload=com.yahoo.ycsb.workloads.CoreWorkload"))
	ycsb_params.append(("readallfields=true"))
	ycsb_params.append(("readproportion={}").format(ycsb_readprop))
	ycsb_params.append(("updateproportion={}").format(ycsb_updateprop))
	ycsb_params.append(("scanproportion={}").format(ycsb_scanprop))
	ycsb_params.append(("insertproportion={}").format(ycsb_insertprop))
	ycsb_params.append(("requestdistribution={}").format(ycsb_distribution))
	write_conf_file(ycsb_params, ycsb_params_fname)
	
	cmdline = ("{} load {} -s -P {}").format(
		ycsb_bin, ycsb_dbname, ycsb_params_fname)
	  # -s prints status every 10 seconds. server (localhost) is specified
	  # in ycsb_params.
	write_conf_file([cmdline], "{}/ycsb-load-cmdline".format(output_dir))
	print_debug(tag, ("calling cmdline={} to load cassandra database "
		"for ycsb").format(cmdline))
	ycsb_stdout.write("# PJH: load phase\n")
	ycsb_stderr.write("# PJH: load phase\n")
	ycsb_stdout.flush()
	ycsb_stderr.flush()

	args = shlex.split(cmdline)
	retcode = subprocess.call(args, stdout=ycsb_stdout, stderr=ycsb_stderr)
	if retcode != 0:
		print_error(tag, ("ycsb load returned non-zero code "
			"{}").format(retcode))
		return None

	return ycsb_params_fname

# ...
def ycsb_run(ycsb_params_fname, output_dir, ycsb_stdout, ycsb_stderr):
	tag = 'ycsb_run'
	global ycsb_bin, ycsb_dbname

	cmdline = ("{} run {} -s -P {}").format(
		ycsb_bin, ycsb_dbname, ycsb_params_fname)
	write_conf_file([cmdline], "{}/ycsb-run-cmdline".format(output_dir))
	print_debug(tag, ("calling cmdline={} to run ycsb against "
		"cassandra").format(cmdline))
	ycsb_stdout.write("\n\n# PJH: run phase\n")
	ycsb_stderr.write("\n\n# PJH: run phase\n")
	ycsb_stdout.flush()
	ycsb_stderr.flush()

	# http://docs.python.org/3/library/subprocess.html#subprocess.call
	args = shlex.split(cmdline)
	retcode = subprocess.call(args, stdout=ycsb_stdout, stderr=ycsb_stderr)
	if retcode != 0:
		print_error(tag, ("ycsb run returned non-zero code "
			"{}").format(retcode))
		return False

	return True

##############################################################################
# Cassandra #
#############

# Creates the initial cassandra keyspace and column family that YCSB needs
# to use. For now, assumes that the cassandra server is running on localhost,
# using the default RPC/thrift port (9160).
def cass_init_keyspace(output_dir, cqlsh_stdout, cqlsh_stderr):
	tag = 'cass_init_keyspace'
	global cqlsh_bin

	cqlsh_cmd_fname = "{}/cqlsh-init-usertable".format(output_dir)
	cqlsh_cmd_lines = []
	cqlsh_cmd_lines.append(("drop keyspace usertable;"))
	  # May cause this error to be output:
	  #   <ErrorMessage code=2300 [Query invalid because of configuration
	  #   issue] message="Cannot drop non existing keyspace 'usertable'.">
	  # and error code 1 to be returned :(
	  # Solution: just retry the command here, since the next command
	  #   that creates the keyspace seems to succeed on the first go,
	  #   to the drop command should succeed on the second go :)
	cqlsh_cmd_lines.append(("create keyspace usertable with replication "
		"= {'class':'SimpleStrategy', 'replication_factor':1};"))
	cqlsh_cmd_lines.append(("use usertable;"))
	cqlsh_cmd_lines.append(("create table data (key text, column1 text, "
		"value text, PRIMARY KEY (key, column1)) with compact storage;"))
	cqlsh_cmd_lines.append(("describe keyspace usertable;"))
	write_conf_file(cqlsh_cmd_lines, cqlsh_cmd_fname)
	print_debug(tag, ("wrote cqlsh commands to intialize cassandra "
		"to {}").format(cqlsh_cmd_fname))

	success = False
	retries = 3   # a few retries may be needed, esp. on first run in a while
	while retries >= 0:
		#print_TODO(tag, ("add support in this method for non-localhost "
		#	"cassandra servers?").format())
		cmdline = "{} --file={} localhost".format(cqlsh_bin, cqlsh_cmd_fname)
		#cmdline = "{} --file={} verbena.cs.washington.edu".format(
		#		cqlsh_bin, cqlsh_cmd_fname)
		print_debug(tag, ("calling cmdline=\"{}\" to set up initial "
			"keyspace etc.").format(cmdline))
		args = shlex.split(cmdline)
		retcode = subprocess.call(args, stdout=cqlsh_stdout,
				stderr=cqlsh_stderr)
		if retcode != 0:
			success = False
			print_warning(tag, ("command \"{}\" returned non-zero code "
				"{}").format(cmdline, retcode))
			retries -= 1
			if retries >= 0:
				print_warning(tag, ("retrying command, {} retries "
					"remaining").format(retries))
				time.sleep(2)
		else:
			print_debug(tag, ("success! initial keyspace setup").format())
			success = True
			retries = 0
			break
	
	return success

def check_for_running_cass():
	tag = 'check_for_running_cass'

	null = open('/dev/null', 'w')

	cmdline = "pgrep -f CassandraDaemon"
	args = shlex.split(cmdline)
	retcode = subprocess.call(args, stdout=null, stderr=null)
	null.close()
	if retcode != 1:
		print_error(tag, ("{} returned code other than 1, "
			"indicating that a Cassandra server may already be running "
			"on this host - kill it first! (try "
			"./reset-cassandras.sh)").format(cmdline))
		return False

	return True

# Starts cassandra as a child process of this script.
# If the output_dir is set, then the pid of the started Cassandra
# server will be saved in a file in that directory; if the output_dir
# is None then it will not be saved.
# Returns: a Popen object which must later be passed to
#   stop_cass_server(), or None on error.
def start_cass_server(output_dir, cass_stdout, cass_stderr):
	tag = 'start_cass_server'
	global cass_startuptime

	success = check_for_running_cass()
	if not success:
		return None

	# Cassandra is dumb and needs to run as root. Using the -f flag tells
	# the cass_bin shell script to execute the cassandra server in the
	# foreground, but unfortunately this doesn't mean that it will
	# *directly* execute it - the cassandra server will still be a child
	# process of the cass_bin shell script. This makes our script less
	# elegant, because we can't directly send a signal to the cassandra
	# server...
	#   Well, it looks like sending a signal to the shell child process
	#   (cass_p - in stop_cass_server()) has the desired effect: the
	#   cassandra server exits after a few seconds. The stdout appears
	#   to indicate a normal cassandra shutdown.
	#     Go with it for now; if it turns out that this doesn't really
	#     shutdown the server in the right way, can switch this script
	#     to use pkill instead.
	# Also, the -p <filename> can be used with bin/cassandra to save
	# the true pid to a file, so that we'll know what it was when we
	# perform our analysis later.
	#   Allegedly... but it doesn't seem to actually work.
	#
	# What the hell - when I run ltrace on cassandra (by setting an
	# environment variable in the sudo command that activates ltrace
	# in the cassandra shell script), it produces no output in
	# ltrace.out, even when I run it manually from the command line.
	# Additionally, starting sudo -> ltrace -> java causes the
	# other parts of this script (e.g. sending signals to kill the
	# cassandra server) to break... so let's just give up on ltraceing
	# cassandra / java for now.
	if output_dir:
		cmdline = "sudo {} -f -p {}/{}".format(
			cass_bin, output_dir, 'target_pid')
		#cmdline = "sudo {} {} -f -p {}/{}".format(ltrace.LTRACE_ENV,
		#	cass_bin, output_dir, 'target_pid')
	else:
		cmdline = "sudo {} -f".format(cass_bin)
		#cmdline = "sudo {} {} -f".format(ltrace.LTRACE_ENV, cass_bin)
	args = shlex.split(cmdline)
	print_debug(tag, ("executing cmdline=\"{}\" as a child process").format(
		cmdline))
	cass_p = subprocess.Popen(args, stdout=cass_stdout, stderr=cass_stderr)

	# Check that Cassandra didn't exit immediately:
	if not cass_p:
		print_error(tag, ("subprocess.Popen for cassandra returned "
			"None; cmdline={}").format(cmdline))
		return None
	if False:
		# timeout support and the TimeoutExpired exception are only
		# added for python 3.3!
		try:
			timeout = 5
			print_debug(tag, ("waiting {} seconds to see if cassandra "
				"server exits immediately").format(timeout))
			retcode = cass_p.wait(timeout = timeout)
			print_error(tag, ("cassandra server already exited with "
				"retcode {}").format(retcode))
			return None
		except subprocess.TimeoutExpired:
			pass
	
	# Cassandra needs like 10-15 seconds to complete its startup process,
	# so sleep for a little while. If we don't do this, then the cqlsh
	# command that comes next will fail.
	#   xxx: is there a less-fragile way to wait for cassandra to be "ready"?
	#if not ltrace.LTRACE_ON:
	#	sleeptime = cass_startuptime
	#else:
	#	# ltrace makes cassandra startup slow :(
	#	sleeptime = cass_startuptime * 3
	sleeptime = cass_startuptime
	print_debug(tag, ("cassandra daemon started (parent shell has pid "
		"{}); waiting {} seconds for it to be ready").format(
		cass_p.pid, sleeptime))
	time.sleep(sleeptime)

	return cass_p

# Note: this method runs sudo shell commands using cass_p.pid - don't
# call it with non-validated input!
def stop_cass_server(cass_p):
	tag = 'stop_cass_server'

	# See notes in start_cass_server(): cass_p is actually the shell
	# script that starts the cassandra server as a child. It looks
	# like sending a signal to the shell script has the desired effect
	# of shutting down the cassandra server though - the only unusual
	# thing is that the child shell process will return a strange
	# error code, which is actually 128 plus the number of the signal
	# that caused the shell to exit:
	# http://stackoverflow.com/a/7294947/1230197.
	#   Alternative shell command if we don't want to send a signal
	#   to a Popen object: sudo pkill -TERM -f CassandraDaemon
	# After switching to Python 3.3, I now get this error when I use
	# .send_signal():
	#   PermissionError: [Errno 1] Operation not permitted
	# Ugh - whatever, just run a sudo shell command instead.

	stopsig = signal.SIGTERM   # SIGINT (Ctrl-c) doesn't work on cassandra
	print_debug(tag, ("sending signal {} to cassandra server's parent "
		"shell process with pid {}").format(stopsig, cass_p.pid))
	#cass_p.send_signal(stopsig)
	subprocess.call(
		("sudo bash -c 'kill -SIGTERM {}'").format(cass_p.pid),
		shell=True)

	if False:    # try this on python 3.3...
		timeout = 30   # usually takes < 5 seconds to exit
		print_debug(tag, ("sending signal {} to cassandra server process "
			"with pid {}; will wait {} seconds for it to exit").format(
			stopsig, cass_p.pid, timeout))
		try:
			retcode = cass_p.wait(timeout=timeout)
		except subprocess.TimeoutExpired:
			print_error(tag, ("timeout expired, cassandra server {} "
				"won't die?").format(cass_p.pid))
			return False
	else:
		print_debug(tag, ("waiting indefinitely for cassandra server "
			"process with pid {} to exit").format(cass_p.pid))
		retcode = cass_p.wait()
	if retcode != 128 + stopsig:
		print_error(tag, ("cassandra's parent shell exited with "
			"retcode {}, expected {} though").format(
			retcode, 128 + stopsig))
		return False
	
	print_debug(tag, ("successfully killed cassandra server").format())
	return True

def cass_check_files():
	tag = 'cass_check_files'
	global cass_dir, ycsb_dir, cass_bin, cqlsh_bin

	if (not os.path.exists(cass_dir) or not os.path.exists(ycsb_dir)):
		print_error(tag, ("expected directory not found: "
			"cass_dir {}, ycsb_dir {}").format(cass_dir, ycsb_dir))
		return False
	
	if (not os.path.exists(cass_bin) or not os.path.exists(cqlsh_bin)
			or not os.path.exists(ycsb_bin)):
		print_error(tag, ("expected binaries not found: "
			"cass_bin {}, cqlsh_bin {}, ycsb_bin {}").format(
			cass_bin, cqlsh_bin, ycsb_bin))
		return False

	return True

# Performs the following steps:
#   - Checks that the Cassandra and YCSB files are in the directories
#     we expect.
#   - Creates files for cassandra stdout and stderr to be directed to.
#   - Removes the cassandra data directory, if it already exists.
#   - Initializes the Cassandra keyspace and column family that are
#     used by YCSB.
# Returns: a big tuple...
def cass_init(output_dir):
	tag = 'cass_init'
	global cass_data_dir

	success = cass_check_files()
	if not success:
		return (False, None, None, None, None)

	init_stdout_fname  = "{}/init-stdout".format(output_dir)
	init_stderr_fname  = "{}/init-stderr".format(output_dir)
	cqlsh_stdout_fname = "{}/cqlsh-stdout".format(output_dir)
	cqlsh_stderr_fname = "{}/cqlsh-stderr".format(output_dir)
	cass_stdout_fname  = "{}/cass-stdout".format(output_dir)
	cass_stderr_fname  = "{}/cass-stderr".format(output_dir)
	ycsb_stdout_fname  = "{}/ycsb-stdout".format(output_dir)
	ycsb_stderr_fname  = "{}/ycsb-stderr".format(output_dir)
	init_stdout  = open(init_stdout_fname, 'w')
	init_stderr  = open(init_stdout_fname, 'w')
	cqlsh_stdout = open(cqlsh_stdout_fname, 'w')
	cqlsh_stderr = open(cqlsh_stderr_fname, 'w')
	cass_stdout  = open(cass_stdout_fname, 'w')
	cass_stderr  = open(cass_stderr_fname, 'w')
	ycsb_stdout  = open(ycsb_stdout_fname, 'w')
	ycsb_stderr  = open(ycsb_stderr_fname, 'w')

	if cass_data_dir != '/var/lib/cassandra':  # double-check!
		print_error(tag, ("double-check that cass_data_dir {} is "
			"set correctly - about to rm -rf it!").format(
			cass_data_dir))
		return False

	# I searched the web a little bit to try to find the best way to
	# execute some commands / some parts of a python script with root
	# privilege, and the rest with normal user privileges. It seems like
	# the best / easiest way to do this is to directly execute the shell
	# commands, but simply use sudo in front of them. This may require
	# entering my password the first time a sudo command is encountered,
	# but it would also be possible to set up password-less sudo I think.
	#
	# A possible alternative would be to use the setuid / setegid / etc.
	# python commands, but I didn't try to figure out exactly how...
	#   http://docs.python.org/3/library/os.html#os.setegid
	cmdline = "sudo rm -rf {}".format(cass_data_dir)
	args = shlex.split(cmdline)
	if args[-1] != cass_data_dir:  # double-check!
		print_error(tag, ("double-check that args[-1] {} is "
			"set correctly - about to rm -rf it!").format(args[-1]))
		return False
	retcode = subprocess.call(args)
	if retcode != 0:
		print_error(tag, ("command \"{}\" returned non-zero code "
			"{}").format(cmdline, retcode))
		return False
	print_debug(tag, ("removed old cassandra data directory {}").format(
		cass_data_dir))

	cass_p = start_cass_server(None, init_stdout, init_stderr)
	success = cass_init_keyspace(output_dir, cqlsh_stdout, cqlsh_stderr)
	if success and cass_p:
		success = stop_cass_server(cass_p)
	else:
		success = False
		if cass_p:
			stop_cass_server(cass_p)

	init_stdout.close()
	init_stderr.close()
	cqlsh_stdout.close()
	cqlsh_stderr.close()

	return (success, cass_stdout, cass_stderr, ycsb_stdout, ycsb_stderr)

def cass_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

def cassandra_exec(output_dir):
	tag = 'cassandra_exec'

	(success, cass_stdout, cass_stderr, ycsb_stdout,
		ycsb_stderr) = cass_init(output_dir)
	if not success:
		print_error(tag, ("cass_init failed, returning no target_pids"))
		return []

	target_pids = []
	tracer = traceinfo('cassandra')

	# If any of the trace steps fails along the way, we can skip some
	# of the rest of the steps, but make sure to still stop the cassandra
	# server and turn tracing off.
	success = True

	# cass_init will start and then stop the Cassandra server, because
	# we want to trace Cassandra while it starts from scratch:
	success = tracer.trace_on(output_dir, descr='starting Cassandra trace')
	if not success:
		print_error(tag, ("trace_on failed, returning before starting "
			"cassandra or ycsb").format())
		return []

	cass_p = start_cass_server(output_dir, cass_stdout, cass_stderr)

	retcode = tracer.trace_checkpoint('after-cass-start',
			targetpid=cass_p.pid)
	if retcode == 'error' or retcode == 'full':
		print_error(tag, ("trace_checkpoint returned {} after "
			"cassandra start, this is unexpected - will return empty "
			"target_pids list").format(retcode))
		success = False
	
	if success:
		ycsb_params_fname = ycsb_load(output_dir, ycsb_stdout, ycsb_stderr)
		if not ycsb_params_fname:
			print_error(tag, ("ycsb_load failed"))
			success = False
		retcode = tracer.trace_checkpoint('after-ycsb-load',
				targetpid=cass_p.pid)
		if retcode == 'error' or retcode == 'full':
			print_error(tag, ("trace_checkpoint returned {} after "
				"ycsb load, this is unexpected - will return empty "
				"target_pids list").format(retcode))
			success = False

	if success:
		success = ycsb_run(ycsb_params_fname, output_dir,
				ycsb_stdout, ycsb_stderr)
		retcode = tracer.trace_checkpoint('after-ycsb-run',
				targetpid=cass_p.pid)
		if retcode == 'error' or retcode == 'full':
			print_error(tag, ("trace_checkpoint returned {} after "
				"ycsb run, this is unexpected - will return empty "
				"target_pids list").format(retcode))
			success = False

	stop_cass_server(cass_p)
	if success:
		retcode = tracer.trace_checkpoint('after-cass-shutdown')
		if retcode == 'error' or retcode == 'full':
			print_error(tag, ("trace_checkpoint returned {} after "
				"cassandra shutdown, this is unexpected - will return empty "
				"target_pids list").format(retcode))
			success = False

	(tracesuccess, buffer_full) = tracer.trace_off(
			descr='ending Cassandra trace')
	cass_cleanup([cass_stdout, cass_stderr, ycsb_stdout, ycsb_stderr])

	if success:
		if not tracesuccess or buffer_full:
			print_error(tag, ("trace buffer filled up before "
				"tracing turned off - considering this an error "
				"here").format())
			success = False
			target_pids = []
		else:
			target_pids.append(cass_p.pid)

	return target_pids

# ugh, why does this have to go at the bottom?
cassandra_app = app_to_run('cass', cassandra_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
