# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# LAMP stack web application: Mediawiki + apache + mysql + memcached.
# 
# Build + setup instructions: do these once / occasionally by hand, not
# done automatically by this script.
#   Ensure that passwordless-sudo is enabled for the user running the script.
#   Follow separate instructions to install, configure and load a
#     Mediawiki application...
#   Verify the pid-file locations listed in global vars below.
#   ...
#
# Note: this script uses timeout features that were added to Python 3.3
# (available in Ubuntu 13.04) - if this is a problem, they should be
# fairly easy to eliminate from the code, just search for "timeout".

from app_scripts.app_browser import *
from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo
import app_scripts.ubuntu_services as ubuntu_services
import signal

# If USE_MANUAL_CLIENT is True, then the automated web browser will not
# be started to send requests to the web server + LAMP stack; instead,
# this script will pause until a Ctrl-C is sent. This allows various
# other workloads to be generated for testing purposes, while still
# tracing the LAMP applications as usual.
USE_MANUAL_CLIENT = False
WHICHBROWSER = 'firefox'   # chrome not tested yet

# Configuration for Mediawiki client workload:
hostname = 'localhost'
wiki_prefix = 'mediawiki/index.php'
#wiki_pages = ['Santoral_católico', 'Salviniales']
random_page = 'Special:Random'
num_pages = 5

service_timeout = 30
	# Fail if it takes longer than service_timeout seconds to start or stop
	# a service.
headless_browser = True
	# Run client Firefox browser in headless mode?

##############################################################################
# Returns a tuple:
#   (A browser webdriver, or None on error;
#    the virtual frame buffer process, or None if not in headless mode).
def start_client(outputdir):
	tag = 'start_client'

	(driver, browser_pid, xvfb_p) = start_browser(outputdir, WHICHBROWSER,
			headless_browser)
	if not browser_pid or browser_pid < 2:
		print_error(tag, ("invalid browser_pid {}").format(browser_pid))
		return (None, None)
	if headless_browser and not xvfb_p:
		driver.quit()
		print_error(tag, ("headless set, but didn't get back an xvfb_p"))
		return (None, None)
	
	# The webdriver object tends to be returned to us here after the
	# Firefox window has appeared, but while it still appears to be
	# processing some stuff to finish its boot sequence. So, wait a
	# little while here. Still, it will take a while for the first
	# page request to come back (due to Mediawiki slowness, not due
	# to browser slowness.
	sleeptime = 5
	print_debug(tag, ("waiting {} seconds for browser to finish booting "
		"up").format(sleeptime))
	time.sleep(sleeptime)

	return (driver, xvfb_p)

# The client is a webdriver object (see app_browser.py).
# Returns: True if the client workload ran as expected, or False if
# there was an error.
def run_client(client, outputdir, tracer, targetpid):
	tag = 'run_client'

	# Current workload: visit the wiki's "Random Page" link num_pages
	# times, in the same/only tab of the client browser.
	# To check that the LAMP stack components are actually being used:
	#   sudo php /usr/share/mediawiki/maintenance/stats.php
	#   echo "stats" | nc localhost 11211

	urls = []
	url_prefix = "http://{}/{}".format(hostname, wiki_prefix)
	for i in range(num_pages):
		urls.append(("{}/{}").format(url_prefix, random_page))
	print_debug(tag, ("calling visit_all_urls({})").format(urls))

	if not tracer.perf_on():
		print_error(tag, ("perf_on() failed, but still continuing"))
	retcode = visit_all_urls(client, urls, False, tracer, WHICHBROWSER,
			targetpid=targetpid, timeoutsok=False)
	tracer.perf_off()

	if retcode == 'success':
		success = True
	elif retcode == 'full':
		print_error(tag, ("visit_all_urls returned {} - consider "
			"this an error? For now, yes").format(retcode))
		success = False
	else:
		print_error(tag, ("visit_all_urls returned {}; will return "
			"success=False").format(retcode))
		success = False

	return success

def stop_client(client, xvfb_p):
	client.quit()   # .quit() exits the entire browser.
	stop_xvfb(xvfb_p)
	return

def service_init(outputdir, service):
	tag = 'service_init'

	service_stdout_fname  = "{}/{}-stdout".format(outputdir, service)
	service_stderr_fname  = "{}/{}-stderr".format(outputdir, service)
	service_stdout  = open(service_stdout_fname, 'w')
	service_stderr  = open(service_stderr_fname, 'w')

	return (service_stdout, service_stderr)

def service_cleanup(files_to_close):
	for f in files_to_close:
		f.close()
	return

# services is an ordered list of the services that need to be started
# in order to run the mediawiki application. This method will start
# the client browser and then the services in the specified order,
# then run the client workload, then will stop the services in the
# reverse order they were started in. The service that we want to
# trace should be last in the services list: tracing will be activated
# just before starting the last service and just after stopping it,
# to minimize the size of the trace file.
#   A potential alternative would be to capture a trace for all of
#   the services at the same time, then copy the trace file and use
#   a different target_pids list for each app that we want to analyze.
#   However, the rest of my trace / analysis infrastructure isn't
#   quite set up to do this right now.
#
# The service names that this method recognizes are in the global
# "expected_services" list (in ubuntu_services.py). I verified that
# for Mediawiki, these
# services can be started in any order and the web app will still
# work.
# 
# Returns: a target_pids list containing the top-level pid of the
# target (last) service, or an empty list on error.
def mediawiki_exec(outputdir, services, manualservice=None):
	tag = 'mediawiki_exec'

	stdouts = []
	stderrs = []
	target_pids = []
	service_pids = []
	target_service = services[-1]
	tracer = traceinfo(target_service)
	tracesuccess = False

	# Initialization: set up stdout and stderr files, and stop
	# any services that may be running.
	for service in services:
		(service_stdout, service_stderr) = service_init(outputdir,
				service)
		stdouts.append(service_stdout)
		stderrs.append(service_stderr)

		(success, service_pid) = ubuntu_services.service_cmd(
				service, 'stop', outputdir, service_stdout,
				service_stderr)

	if USE_MANUAL_CLIENT:
		print_debug(tag, ("skipping browser client start"))
		(client, xvfb_p) = (None, None)
	else:
		# start_client() returns a client driver and the subprocess.Popen
		# object for the virtual frame buffer (if we're in headless mode).
		(client, xvfb_p) = start_client(outputdir)
		if not client:
			service_cleanup(stdouts + stderrs)
			print_error(tag, ("start_client() failed, returning empty "
				"target_pids"))
			return []
		print_debug(tag, ("client started successfully").format())

	# Start all services, enabling tracing before starting the last
	# one:
	for i in range(len(services)):
		service = services[i]
		
		if i == len(services) - 1 and manualservice is None:
			success = tracer.trace_on(outputdir,
					descr="starting {}".format(service))
			if not success:
				print_error(tag, ("trace_on failed, breaking out of "
					"start loop"))
				break

		(success, service_pid) = ubuntu_services.service_cmd(
				service, 'start', outputdir, stdouts[i], stderrs[i])

		if success and service_pid > 1:
			service_pids.append(service_pid)
			print_debug(tag, ("appended service_pid {} for {}").format(
				service_pids[-1], service))
		else:
			print_error(tag, ("start {} returned {} or could not find "
				"pid ({}), so breaking out of start loop").format(
				service, success, service_pid))
			break

	tracemanualservice = False
	
	if success and manualservice != None:
		if tracemanualservice:
			success = tracer.trace_on(outputdir,
					descr="starting {}".format(service))
		if success:
			signal.signal(signal.SIGINT, signal_handler_nop)
			print(("Ok, tracing is on, start the {} service, wait "
				"a little while (perhaps issue a separate web request "
				"to verbena.cs.washington.edu/mediawiki/index.php/"
				"Navidad to ensure mediawiki setup is "
				"working) and "
				"press Ctrl-C to begin the client workload. While "
				"workload is running, note the pid of your "
				"service!").format(manualservice))
			signal.pause()   # Note: Linux-only
			signal.signal(signal.SIGINT, signal.SIG_DFL)
			success = True
	
	if success:
		if USE_MANUAL_CLIENT:
			# Pause until Ctrl-C (SIGINT) is received. Call a nop signal
			# handler when signal is received, then reset signal behavior
			# back to default.
			#   http://docs.python.org/3/library/signal.html
			signal.signal(signal.SIGINT, signal_handler_nop)
			print(("Paused - execute your client workload then press "
				"Ctrl-C to stop trace."))
			signal.pause()   # Note: Linux-only
			signal.signal(signal.SIGINT, signal.SIG_DFL)
			success = True
		else:
			success = run_client(client, outputdir, tracer,
					service_pids[-1])

	if success and manualservice is None:
		target_pids.append(service_pids[-1])
		print_debug(tag, ("client succeeded, {} target_pids: "
			"{}").format(target_service, target_pids))
	elif success and manualservice != None:
		signal.signal(signal.SIGINT, signal_handler_nop)
		print(("Ok, client workload completed, kill the {} service "
			"then hit Ctrl-C to turn off tracing and stop other "
			"services.").format(manualservice))
		signal.pause()   # Note: Linux-only
		signal.signal(signal.SIGINT, signal.SIG_DFL)
		success = True
	else:
		if len(service_pids) > 0:
			tpid = service_pids[-1]
		else:
			tpid = -1234
		print_error(tag, ("service-start or trace_on or run_client "
			"returned failure; will just clean up and return now. "
			"target_pids will be empty, but echo {} > target_pids "
			"to analyze trace anyway").format(tpid))

	for i in range(len(services) - 1, -1, -1):
		service = services[i]

		(success, ignore) = ubuntu_services.service_cmd(
				service, 'stop', outputdir, stdouts[i], stderrs[i])

		if not success:
			print_error(tag, ("received error on {} stop, will "
				"continue stopping other services").format(service))

		# Stop trace *after* stopping target service:
		if (i == len(services) - 1 and 
			(manualservice is None or tracemanualservice)):
			(tracesuccess, buffer_full) = tracer.trace_off(
					descr="stopping {}".format(service),
					targetpid=service_pids[i])

	if not tracesuccess or buffer_full:
		print_error(tag, ("trace buffer filled up before "
			"tracing turned off - considering this an error "
			"here").format())
		success = False
		target_pids = []

	if not USE_MANUAL_CLIENT:
		stop_client(client, xvfb_p)
	service_cleanup(stdouts + stderrs)

	if manualservice:
		print_warning(tag, ("target_pids is currently {}, but "
			"this is not correct! Fill in the target_pids file "
			"with the correct pid manually.").format(target_pids))

	return target_pids

def lamp_apache_exec(outputdir):
	services = ['memcached', 'mysql', 'apache2']
	return mediawiki_exec(outputdir, services)

def lamp_apache_manual_exec(outputdir):
	services = ['memcached', 'mysql']
	return mediawiki_exec(outputdir, services, manualservice='apache')

def lamp_memcached_exec(outputdir):
	services = ['mysql', 'apache2', 'memcached']
	return mediawiki_exec(outputdir, services)

def lamp_mysql_exec(outputdir):
	services = ['memcached', 'apache2', 'mysql']
	return mediawiki_exec(outputdir, services)

def lamp_mysql_manual_exec(outputdir):
	services = ['memcached', 'apache2']
	return mediawiki_exec(outputdir, services, manualservice='mysql')

# First arg is "appname" member: used to construct output directory.
LAMP_apache_app = app_to_run('apache', lamp_apache_exec)
LAMP_apache_manual_app = app_to_run('apache', lamp_apache_manual_exec)
LAMP_memcached_app = app_to_run('lamp-mcache', lamp_memcached_exec)
LAMP_mysql_app = app_to_run('mysql', lamp_mysql_exec)
LAMP_mysql_manual_app = app_to_run('mysql', lamp_mysql_manual_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
