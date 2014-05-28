# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# This file contains helper methods for dealing with Ubuntu services.

from trace.traceinfo_class import traceinfo
from util.pjh_utils import *
import trace.run_common as run
import signal
import subprocess
import time

# List of services that this script knows how to handle:
KNOWN_SERVICES = ['apache2', 'memcached', 'mysql']

SERVICE_PIDFILES = {
		'apache2'   : '/var/run/apache2.pid',
		'memcached' : '/var/run/memcached.pid',
		'mysql'     : '/var/run/mysqld/mysqld.pid'
	}
SERVICE_CMD_TIMEOUT = 30

# This method knows how to read the pid file or how to parse ps(1) output
# for all of the services in the global KNOWN_SERVICES list.
# Returns: the pid of the service's top-level process, or -1 on error.
def get_service_pid(service):
	tag = 'get_service_pid'

	if service not in KNOWN_SERVICES:
		print_error(tag, ("unexpected service {}").format(service))
		return -1

	try:
		pidfile = SERVICE_PIDFILES[service]
	except KeyError:
		print_error(tag, ("couldn't get pidfile for {}").format(service))
		return -1

	pid = run.read_pidfile(pidfile)

	return pid

# Uses the Ubuntu service(8) command to run the specified command
# (e.g. start, stop) for the specified service. service(8) is
# convenient and avoids the problem of having to correctly set up
# environment variables and command-line parameters to start these
# services ourself. One drawback of service(8), however, is that it
# doesn't tell us the pid of the service when it it started, so we
# call app-specific methods here to get the pid of the service
# (usually this can be done easily by reading a "pid file" that each
# service establishes, but in future cases it may be necessary to
# parse ps(1) output, like is done for the chrome+chromedriver script).
#
# WARNING: this method issues sudo shell commands - this is a security
# hazard if uncontrolled input is passed to this method!
#
# Returns a tuple:
#   (True if the service command returned successfull, False if not;
#    the pid of the started service if the command was 'start', or -1
#    if the pid could not be found for some reason.)
def service_cmd(service, command, outputdir, service_stdout, service_stderr):
	tag = 'service_cmd'

	if service not in KNOWN_SERVICES:
		print_error(tag, ("unexpected service {}").format(service))
		return (False, -1)
	if command not in ['start', 'stop']:
		# be a little bit safe anyway...
		print_error(tag, ("command {} not expected - not executing "
			"service command to avoid a security hazard!").format(
			command))
		return (False, -1)

	cmdline = "sudo bash -c 'service {} {}'".format(service, command)
	print_debug(tag, ("cmdline: {}").format(cmdline))
	
	# Expected return code is 0 in pretty much every case: stopping a
	# service that is running or is already stopped, starting a service
	# that is stopped or is already running (we might want to try to
	# detect this last case here, but whatever).
	#   Actually, it turns out that the value returned when starting
	#   an already-started service is service-dependent - mysql returns
	#   1, apache2 and memcached return 0. Whatever.
	# I haven't tried any other commands besides start and stop.
	try:
		retcode = subprocess.call(cmdline, shell=True,
				stdout=service_stdout, stderr=service_stderr,
				timeout=SERVICE_CMD_TIMEOUT)
		time.sleep(1)
		  # seems like a good idea to pause a tiny bit after starting
		  # or stopping service, so that whatever we do next (perhaps
		  # re-starting the service, examining its pid file, etc.)
		  # knows "for sure" that the service call is complete.
	except subprocess.TimeoutExpired:
		print_error(tag, ("command \"{}\" timed out! ({} "
			"seconds)").format(cmdline, SERVICE_CMD_TIMEOUT))
		return (False, -1)
	
	if retcode != 0:
		if command == 'stop' and service == 'mysql' and retcode == 1:
			# Ignore: 1 is returned if stopped when mysql not running
			pass
		else:
			# I've hit errors here for apache2 start, with this in the
			# stderr:
			#   (98)Address already in use: make_sock: could not bind
			#   to address [::]:80
			#   (98)Address already in use: make_sock: could not bind
			#   to address 0.0.0.0:80
			#   no listening sockets available, shutting down
			#   Unable to open logs
			# Todo: retry some number of times in this method when this
			# particular error is hit...
			print_error(tag, ("command \"{}\" returned non-0 code "
				"{}, returning now").format(cmdline, retcode))
			return (False, -1)

	if command == 'start':
		# Is there any race condition between the start of a service
		# and the presence of the pid file? Not in my experience, but
		# add a little tiny wait just in case. Also, the services
		# remove their pid files when they are stopped, so there should
		# be no chance of getting a stale pid.
		#   Actually, maybe there is a race condition - when trying to
		#   read the apache2 pidfile once, I got an error where the
		#   line was read from the file, but it didn't match my simple
		#   pid regex. So I bumped up the tiny wait a little more here,
		#   and added a retry loop in get_service_pid() -> read_pidfile().
		time.sleep(1)
		service_pid = get_service_pid(service)
		print_debug(tag, ("get_service_pid({}) returned {}").format(
			service, service_pid))
	else:
		service_pid = 0   # caller should ignore

	return (True, service_pid)

#############################################################################

# This method is designed to be used as the execfn for an app_to_run
# object for any arbitrary ubuntu service ("service --status-all") where
# we want to start + trace the service, run its client manually, and
# then stop the service. The service must be in the global KNOWN_SERVICES
# list elsewhere in this file.
# 
# Returns: a target_pids list containing the top-level pid of the apache
# process, or an empty list on error.
def runservice_manualclient(outputdir, service):
	tag = 'runservice_manualclient'

	if service not in KNOWN_SERVICES:
		print_error(tag, ("service {} not in KNOWN_SERVICES {}, "
			"returning empty target_pids now").format(service,
			KNOWN_SERVICES))
		return []

	target_pids = []
	tracer = traceinfo(service)

	(service_stdout, service_stderr) = run.stdout_stderr_init(
			outputdir, service)

	(success, meh) = service_cmd(service, 'stop',
			outputdir, service_stdout, service_stderr)
	if not success:
		print_error(tag, ("initial {} stop failed, returning [] "
			"now").format(service))
		for f in [service_stdout, service_stderr]:
			f.close()
		return []

	success = tracer.trace_on(outputdir,
			descr="starting {}".format(service))
	if not success:
		print_error(tag, ("trace_on failed, returning [] now"))
		for f in [service_stdout, service_stderr]:
			f.close()
		return []

	(success, service_pid) = service_cmd(service, 'start',
			outputdir, service_stdout, service_stderr)
	if service_pid < 2:
		success = False

	# If service start didn't succeed, we'll skip the client execution,
	# but we'll still try to stop the service and then turn tracing
	# off.
	if success:
		# Pause until Ctrl-C (SIGINT) is received. Call a nop signal
		# handler when signal is received, then reset signal behavior
		# back to default.
		#   http://docs.python.org/3/library/signal.html
		signal.signal(signal.SIGINT, run.signal_handler_nop)
		print(("Tracing is on and {} service is started").format(service))
		print(("Run your client, then press Ctrl-C to stop the "
			"service and disable tracing"))
		signal.pause()   # Note: Linux-only
		signal.signal(signal.SIGINT, signal.SIG_DFL)
		success = True
	
	service_cmd(service, 'stop', outputdir, service_stdout, service_stderr)

	# Stop trace *after* stopping service.
	(tracesuccess, buffer_full) = tracer.trace_off(
			"stopping {}".format(service), service_pid)
	if not tracesuccess:
		print_error(tag, ("trace_off failed"))
		success = False
	elif buffer_full:
		print_error(tag, ("trace buffer filled up before "
			"tracing turned off - considering this an error "
			"here").format())
		success = False
	
	for f in [service_stdout, service_stderr]:
		f.close()

	if success:
		print_debug(tag, ("everything ran successfully, appending "
			"service_pid {} to target_pids and returning").format(
			service_pid))
		target_pids.append(service_pid)
	else:
		print_error(tag, ("something failed, so not appending "
			"service_pid {} to target_pids").format(service_pid))
		target_pids = []

	return target_pids

if __name__ == '__main__':
	print_error_exit("not an executable module")
