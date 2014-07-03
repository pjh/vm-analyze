# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Automation script for Firefox and Chrome. For now, just opens some
# number of web pages in one or many windows; no interaction with the
# pages is performed.
# For now, the default Google Chrome browser is used - I haven't added
# support here for a Chromium compiled from source (e.g. with my own
# libs) yet.
# 
# Setup steps: perform these once (not automated by this script)
#   Install selenium python bindings (version 2.39.0) into default
#   python directories (/usr/local/lib/python3.3/dist-packages/ on
#   my system)
#     Download latest source: https://pypi.python.org/pypi/selenium
#     python3 setup.py build
#     sudo python3 setup.py install
#
#   Ensure that Chrome is installed at /usr/bin/google-chrome
#   Download the Chromedriver (interface between Chrome and selenium):
#     http://chromedriver.storage.googleapis.com/index.html
#     (I used 2.8 initially, switched to 2.9 on syscluster)
#   Unzip the Chromedriver, set directory below
#
#   Check that the url files and other options below are set up as
#   desired...
#
# Observation: the results for firefox may vary across runs because of
# stupid "dbus" processes that may or may not be launched. Here are a
# couple of example process_groups:
#  ['firefox-25886', 'which-25887', 'firefox-25889', 'dbus-launch-25890',
#   'dbus-launch-25922', 'gst-plugin-scan-25957', 'gst-plugin-scan-25958']
#  ['firefox-25746', 'which-25747', 'firefox-25751', 'dbus-launch-25752',
#   'dbus-launch-25753', 'dbus-daemon-25754', 'dbus-launch-25755',
#   'dbus-daemon-25756',   'dbus-daemon-25757', 'gconfd-2-25758',
#   'dbus-launch-25785', 'gst-plugin-scan-25816', 'gst-plugin-scan-25817']
# Ugh.

from app_scripts.app_to_run_class import *
from trace.run_common import *
import selenium
from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.keys import Keys
from trace.traceinfo_class import traceinfo
import time
from util.pjh_utils import *

# Open all urls in the same window or each in a new window?
SEPARATE_WINDOWS = True

# If PATTERN_OPEN and PATTERN_CLOSE are set, then PATTERN_OPEN windows will
# be opened, then PATTERN_CLOSE windows will be closed, then more will be
# opened, and so on until the urls list is exhausted.
PATTERN_OPEN  = 5
PATTERN_CLOSE = 1

# Run firefox in a virtual X frame buffer, or attempt to start firefox
# instance normally? Non-headless should work if running this script
# locally or with X forwarding enabled
# (e.g. ssh -X pjh@verbena.cs.washington.edu).
#   Does running in headless more or not impact the virtual memory
#   results at all? Not that I can tell - I compared runs of firefox
#   and of Chrome in headless mode and normal mode (via ssh -X), and
#   found that other factors (like the dbus crap mentioned above) had
#   some variable impact across runs, but headless mode did not appear
#   to have any effect.
#headless = False
headless = True

# Use my own built version of Firefox, or use the standard
# /usr/bin/firefox?
#   I thought that this was finally working with my automated script
#   here, but it appears that sometimes (always?) calling driver.quit()
#   hangs with my firefox?
#use_my_firefox = True
use_my_firefox = False

# This script will attempt to navigate to all of the URLs that are
# listed in this file.
browser_urls = "{}/app_browser_urls_30.txt".format(conf_dir)
#browser_urls = None   # use "default urls"

# Since there's no good way to determine when the page load has
# completed, we'll wait for the specified timeout value for each page.
# Actually, it looks like the selenium .get() method usually doesn't
# return until the page is mostly / completely loaded (some AJAX etc.
# code may still be running), so it's probably ok to set this value
# fairly low.
pageloadtime = 6

ff_dir = ("{}/research/virtual/apps/test-root/firefox-notstripped").format(
		home_dir)
#ff_dir = '/usr/bin'
ff_cmd =  "{}/firefox".format(ff_dir)
ff_opts = "...".format()

CHROMEDRIVER_BIN = ("{}/selenium-chromedriver/chromedriver").format(apps_dir)
#CHROMEDRIVER_BIN = ("{}/chromedriver-2.9").format(apps_dir)

default_urls = [
		'http://en.wikipedia.org/wiki/Dynamic_linker',
		'http://www.cs.washington.edu',
	]

##############################################################################

valid_browsers = ['firefox', 'chrome']

# Navigates the browser controlled by driver to the specified URL.
# Returns: True if the page loaded before a timeout was thrown, False
#   if the page load timed out.
def visit_url(driver, url):
	tag = 'visit_url'

	# webdriver/support/expected_conditions.py in selenium webdriver
	# code has very specific conditions that can be waited for (with
	# a timeout value), but nothing general like "wait for page to
	# finish loading". In my experience, driver.get() won't return
	# until most/all of the page has loaded (e.g. it will wait a
	# long time for a slow mediawiki request to return), but will
	# return before AJAX / plugin / etc. code has finished running
	# in the browser.

	#print("PJH: calling driver.get({})".format(url))
	print_debug(tag, ("navigating to: {}").format(url))
	try:
		driver.get(url)
	except selenium.common.exceptions.TimeoutException:
		# I got this exception once when visiting
		# http://localhost/mediawiki/index.php/Special:Random from
		# a headless firefox browser; apparently it waited 30 minutes
		# before throwing this exception!
		# See PAGELOAD_TIMEOUT_MINS - I've attempted to reduce this
		# timeout to 3 minutes instead, but who knows if it works.
		#
		# I also got this page when visiting www.hao123.com (from the
		# alexa url list) - apparently this page never actually
		# finishes loading, it just sits and spins forever.
		print_error(tag, ("selenium TimeoutException when "
			"visiting url {}").format(url))
		return False
	except ConnectionResetError:
		# I got this output during one run with a manually-started
		# apache2 server:
		# DEBUG: visit_url: navigating to: http://localhost/mediawiki/index.php/Special:Random
		# Traceback (most recent call last):
		#   File "./run_apps.py", line 134, in <module>
		#     success = run_app(app, app_output_dir)
		#   File "./run_apps.py", line 31, in run_app
		#     success = app.execute(app_output_dir)
		#   File "/home/pjh/research/virtual/measure/app_to_run_class.py",
		#   line 63, in execute
		#     target_pids = self.execfn(outputdir)
		#   File "/home/pjh/research/virtual/measure/app_LAMP.py", line 420,
		#   in lamp_apache_manual_exec
		#   File "/home/pjh/research/virtual/measure/app_LAMP.py", line 361,
		#   in mediawiki_exec
		#   File "/home/pjh/research/virtual/measure/app_LAMP.py", line 112,
		#   in run_client
		#   File "/home/pjh/research/virtual/measure/app_browser.py",
		#   line 509, in visit_all_urls
		#     success = visit_url(driver, url)
		#   File "/home/pjh/research/virtual/measure/app_browser.py",
		#   line 129, in visit_url
		#     driver.get(url)
		#   File "/usr/local/lib/python3.3/dist-packages/selenium-2.39.0-
		#   py3.3.egg/selenium/webdriver/remote/webdriver.py", line 176, in get
		#     self.execute(Command.GET, {'url': url})
		#   ...
		#   File "/usr/lib/python3.3/http/client.py", line 316, in _read_status
		#     line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
		#   File "/usr/lib/python3.3/socket.py", line 297, in readinto
		#     return self._sock.recv_into(b)
		# ConnectionResetError: [Errno 104] Connection reset by peer
		print_error(tag, ("python threw ConnectionResetError... TODO "
			"here: retry url?"))
		return False


	# Avoid this error: "UnicodeEncodeError: 'ascii' codec can't encode
	# character '\xed' in position 41: ordinal not in range(128)" -
	# http://stackoverflow.com/a/9942885/1230197.
	title = driver.title.encode('utf-8')
	print_debug(tag, ("page title is now: {}").format(title))
	print_debug(tag, ("waiting {} seconds for client-side code "
		"to finish running").format(pageloadtime))
	time.sleep(pageloadtime)

	# Other stuff we could do in this function:
	#   Call driver.get_location(): ensure that url hasn't changed?
	#   Call driver.get_all_window_ids(), get_all_window_names(),
	#     get_all_window_titles(): make sure nothing new has popped
	#     up? Always force the _original_ window to be selected?

	return True

# Optional display arg: if not None, then the DISPLAY environment
# variable will be set to this string before the webdriver / firefox
# instance is started. This can be used for headless operation by
# creating an Xvfb on this display first.
# Returns a tuple:
#   (A Selenium webdriver object, or None on error;
#    pid of the browser process).
def start_firefox_webdriver(display):
	tag = 'start_firefox_webdriver'

	# In order to specify my particular firefox with my particular
	# environment variables, we can't just simply call
	# "webdriver.Firefox()" - we must first set up the environment
	# variables, then create a FirefoxBinary instance with the desired
	# path (which will inherit these environment variables), then
	# pass this FirefoxBinary instance to the webdriver constructor.
	# Relevant files in webdriver source:
	#   webdriver/firefox/webdriver.py
	#   webdriver/firefox/firefox_binary.py
	# Web pages:
	#  http://docs.python.org/3/library/os.html?highlight=os.environ#os.environ

	orig_environ = os.environ.copy()
	try:
		library_path = os.environ["LD_LIBRARY_PATH"]
	except KeyError:
		library_path = ''
	try:
		run_path = os.environ["LD_RUN_PATH"]
	except KeyError:
		run_path = ''
	print(("PJH: original environment: LD_LIBRARY_PATH={}, "
		"LD_RUN_PATH={}").format(library_path, run_path))
	print_debug(tag, ("orig_environ: {}").format(orig_environ))

	ff_path = None
	if use_my_firefox:
		# All of this code works as expected, but when Firefox is starting
		# up, an error appears:
		#   /bin/sh: error while loading shared libraries: __vdso_time:
		#     invalid mode for dlopen(): Invalid argument
		# Part of the problem is that the Firefox webdriver depends on a
		# damn shared library that is shipped directly with the Selenium
		# python bindings. I tried downloading the Selenium source code
		# and re-building the library from scratch, and got this working,
		# but it didn't completely resolve the error. Apparently somewhere
		# in the Selenium startup process a shell (/bin/sh) is invoked
		# to perform some operation, and the execution of this shell
		# doesn't match up with the environment variables that need to
		# be set for my firefox binary, spitting out this error. This
		# eventually leads to this Selenium python error:
		#   selenium.common.exceptions.WebDriverException: Message:
		#   'The browser appears to have exited before we could connect.
		#   The output was: b"XPCOMGlueLoad error for file /home/pjh/research/
		#   virtual/apps/test-root/firefox-notstripped/libxul.so:\\
		#   nlibXrender.so.1: cannot open shared object file: No such file
		#   or directory\\nCouldn\'t load XPCOM.\\n"'
		# Ugh.
		# Note!: without changing anything else, commenting out the
		# LD_PRELOAD of the x_ignore_nofocus.so library in the webdriver
		# code does not immediately appear to break the automated Python
		# webdriver code! Doing this seems like a good idea; I guess
		# trying to rebuild the library may have been a red herring, and
		# the real problem is the /bin/sh process that's started and
		# fails... (that could be a red herring too; I don't exactly
		# see why that leads to the selenium XPCOM error...)
		#   In any case, trying to fuck around with these shared libraries
		#   all the time is clearly unsustainable; I need a system where
		#   my custom-built libc, libstdc++, and other libraries are
		#   actually installed in the default GLOBAL directories.
		for (key, value) in newlibs_envmap.items():
			try:
				origval = os.environ[key]
				print_debug(tag, ("changing os.environ[{}] from {} to "
					"{}").format(key, origval, value))
			except KeyError:
				print_debug(tag, ("inserting into os.environ[{}] = {}").format(
					key, value))
			os.environ[key] = value
		ff_path = ff_cmd

	if display:
		os.environ["DISPLAY"] = display
		print_debug(tag, ("set os.environ[DISPLAY]={} for headless "
			"operation").format(os.environ["DISPLAY"]))

	print_debug(tag, ("instantiating FirefoxBinary with path {}").format(
		ff_path))
	ff_binary = FirefoxBinary(firefox_path=ff_path)

	# Once the FirefoxBinary() has been instantiated, it has already made
	# its own copy of the environment (which it passes to Popen()), so
	# we can restore the original environment here, to avoid any further
	# commands in this script from getting env vars pointing to our
	# "newlibs".
	os.environ = orig_environ
	print_debug(tag, ("restored original environment").format())

	try:
		driver = webdriver.Firefox(firefox_binary=ff_binary)
	except selenium.common.exceptions.WebDriverException as e:
		# See common/exceptions.py in selenium code
		print_error(tag, ("caught WebDriverException: {}").format(
			e.msg))
		#print_error(tag, ("WebDriverException stack trace: {}").format(
		#	e.stacktrace))
		driver = None

	if not driver:
		print_error(tag, ("webdriver.Firefox() returned None").format())
		return (None, -1)
	try:
		library_path = os.environ["LD_LIBRARY_PATH"]
	except KeyError:
		library_path = ''
	try:
		run_path = os.environ["LD_RUN_PATH"]
	except KeyError:
		run_path = ''
	print(("PJH: restored environment: LD_LIBRARY_PATH={}, "
		"LD_RUN_PATH={}").format(library_path, run_path))

	# Get pid of webdriver: easy for firefox, possible but a little
	# tricker for Chrome. driver is a WebDriver object
	# (webdriver/firefox/webdriver.py in Selenium code), containing a
	# FirefoxBinary object (webdriver/firefox/firefox_binary.py), which
	# contains a Popen object once the driver is started.
	# http://stackoverflow.com/a/13650111/1230197
	if (driver.binary and driver.binary.process and 
			type(driver.binary.process) is subprocess.Popen):
		pid = driver.binary.process.pid
	else:
		print_unexpected(True, tag, ("unable to get pid from firefox "
			"driver {}; binary {}, process {}").format(driver,
			driver.binary, driver.process))
		pid = -1

	return (driver, pid)

# Optional display arg: if not None, then the DISPLAY environment
# variable will be set to this string before the webdriver / firefox
# instance is started. This can be used for headless operation by
# creating an Xvfb on this display first.
# Returns a tuple:
#   (A Selenium webdriver object, or None on error;
#    pid of the browser process).
def start_chrome_webdriver(display, outputdir):
	tag = 'start_chrome_webdriver'

	# Haven't tried this yet:
	# In order to specify my particular Chromium with my particular
	# environment variables, we can't just simply call
	# "webdriver.Chrome()" - we must first set up the environment
	# variables, then create a ChromeBinary (?) instance with the desired
	# path (which will inherit these environment variables), then
	# pass this ChromeBinary instance to the webdriver constructor.
	# Relevant files in webdriver source:
	#   webdriver/chrome/webdriver.py
	#   webdriver/chrome/service.py - wrapper around the chromedriver "service"
	# Web pages:
	#  http://docs.python.org/3/library/os.html?highlight=os.environ#os.environ

	orig_environ = os.environ.copy()

	use_chromium = False    # never tried this yet...
	if use_chromium:
		try:
			library_path = os.environ["LD_LIBRARY_PATH"]
		except KeyError:
			library_path = ''
		try:
			run_path = os.environ["LD_RUN_PATH"]
		except KeyError:
			run_path = ''
		print(("PJH: original environment: LD_LIBRARY_PATH={}, "
			"LD_RUN_PATH={}").format(library_path, run_path))
		print_debug(tag, ("orig_environ: {}").format(orig_environ))

		chromium_path = None
		use_my_chromium = False
		if use_my_chromium:
			for (key, value) in newlibs_envmap.items():
				try:
					origval = os.environ[key]
					print_debug(tag, ("changing os.environ[{}] from {} to "
						"{}").format(key, origval, value))
				except KeyError:
					print_debug(tag, ("inserting into os.environ[{}] "
						"= {}").format(key, value))
				os.environ[key] = value
			chromium_path = chromium_cmd

	if display:
		os.environ["DISPLAY"] = display
		print_debug(tag, ("set os.environ[DISPLAY]={} for headless "
			"operation").format(os.environ["DISPLAY"]))

	if use_chromium:
		print_debug(tag, ("instantiating ChromeBinary with path {}").format(
			chromium_path))
		chromium_binary = ChromeBinary(chrome_path=chromium_path)

		driver = webdriver.Chrome(CHROMEDRIVER_BIN,
				chrome_binary=chromium_binary)
		if not driver:
			print_error(tag, ("webdriver.Chrome() returned None").format())
			return (None, -1)

		# Once the ChromeBinary() has been instantiated, it has already made
		# its own copy of the environment (which it passes to Popen()), so
		# we can restore the original environment here, to avoid any further
		# commands in this script from getting env vars pointing to our
		# "newlibs".
		os.environ = orig_environ
		print_debug(tag, ("restored original environment").format())

	# Ok, ignore the clutter above for now - this is the real code for
	# a standard Chrome startup.
	# The startup process can take a while - first of all, if Chrome
	# hasn't been started recently, then the selenium / chromedriver
	# code may time out with "selenium.common.exceptions.WebDriverException:
	# Message: chrome not reachable". If this happens, just run the
	# script again I guess. Then, even after Chrome starts, it
	# may take a while for it to finish "loading" (note that the default
	# url it will always start from is "data:,", for some reason), so
	# we'll wait a little bit for that loading to finish.
	#
	# webdriver.Chrome() is actually instantiating the WebDriver object
	# defined in webdriver/chrome/webdriver.py in the selenium code -
	# see webdriver/__init__.py for an explanation of the way that a
	# dozen different "WebDriver" objects in the code are confusingly
	# renamed when the top-level "webdriver" is used. Anyway, the
	# __init__ method for this object has some options, including a
	# ChromeOptions() object (which is similarly renamed from another
	# actual object in the code, as seen in webdriver/__init__.py).
	print_debug(tag, ("starting Chrome: webdriver.Chrome({})").format(
		CHROMEDRIVER_BIN))

	# Be sure to set the service_log_path argument to webdriver.Chrome()
	# to see log messages from the chromedriver binary (this arg
	# overrides the --log-path if specified in the service_args). We
	# still set the --verbose service_arg (run 'chromedriver -h' to see
	# its options).
	# 
	# Unbelievable: for some reason, when running on stjohns, the
	# chromedriver log shows that it's trying to do this:
	#   Launching chrome: /scratch/pjh/vmstudy-apps/chromium ...
	#
	# What the hell? Nowhere at all in this script or in my environment
	# have I specified vmstudy-apps or vmstudy-apps/chromium at all -
	# is the /scratch/pjh/vmstudy-apps/chromedriver-2.9 somehow
	# searching for nearby chrome / chromium binaries????!?!?!?!?!
	# /scratch/pjh/vmstudy-apps/chromium isn't even a binary file, it's
	# a directory!
	# This is bullshit, but fix it by explicitly specifying the default
	# google-chrome binary (the one that the stupid chromedriver
	# *should* use, that's in my path). Then, the chromedriver log
	# shows this, as expected:
	#   Launching chrome: /usr/bin/google-chrome ...
	# I described this problem in a SO answer:
	# http://stackoverflow.com/a/22735763/1230197
	try:
		service_log_path = "{}/chromedriver.log".format(outputdir)
		options = webdriver.ChromeOptions()
		options.binary_location = '/usr/bin/google-chrome'
		  # /usr/bin/google-chrome symlinks (eventually) to
		  # /opt/google/chrome/google-chrome.
		#options.add_argument("--profile-directory=vmstudy")
		  # To avoid interference on syslab/syscluster machines, use a
		  # separate clean profile-directory for chrome auto-execution
		print_debug(tag, ("using chrome_options: binary_location={}, "
			"arguments={}. Chromedriver log will be written to {}").format(
			options.binary_location, options.arguments, service_log_path))
		service_args = ['--verbose']
		driver = webdriver.Chrome(executable_path=CHROMEDRIVER_BIN,
				service_args=service_args,
				# port=int(someportnumber),
				service_log_path=service_log_path,
				chrome_options=options)
	except selenium.common.exceptions.WebDriverException as e:
		# Possible causes of exceptions:
		#   Xvfb process had failed to start before starting chrome
		#   chrome process was already running when this script was
		#     started
		#   Random errors that don't happen if you re-run this script.
		print_error(tag, ("caught WebDriverException: {}").format(
			e.msg))
		print_error(tag, ("webdriver.Chrome() threw exception, "
			"returning error with no driver started").format())
		return (None, -1)

	waittime = 10
	print_debug(tag, ("waiting {} seconds for window to finish loading"
		"...").format(waittime))
	time.sleep(waittime)
	if not driver:
		print_error(tag, ("webdriver.Chrome() returned None").format())
		return (None, -1)

	if display:
		os.environ = orig_environ
		print_debug(tag, ("restored original environment").format())

	# Get pid of webdriver: for Chrome, driver.service.process is a
	# Popen instance for the *chromedriver*, not for chrome itself,
	# so we have to examine the children of the chromedriver process.
	#   http://stackoverflow.com/a/13650111/1230197
	#   webdriver/chrome/service.py
	#   webdriver/chrome/webdriver.py
	# Ugh - could use the "psutil" python package to get children
	# somewhat easily, or could just parse pstree output myself...
	#   https://pypi.python.org/pypi?:action=display&name=psutil#downloads
	#
	# The output of "ps -ejH" looks like this:
	#   26778 26778 26778 pts/32   00:00:00         bash
	#     492   492 26778 pts/32   00:00:00           python3
	#     535   492 26778 pts/32   00:00:00             chromedriver
	#     538   492 26778 pts/32   00:00:00               chrome
	#     545   492 26778 pts/32   00:00:00                 chrome
	#     546   492 26778 pts/32   00:00:00                 chrome-sandbox
	#     547   492 26778 pts/32   00:00:00                   chrome
	#     551   492 26778 pts/32   00:00:00                     nacl_helper
	#     552   492 26778 pts/32   00:00:00                     chrome
	#     580   492 26778 pts/32   00:00:00                       chrome
	#     589   492 26778 pts/32   00:00:00                       chrome
	# Let's assume that the chromedriver only starts one chrome process -
	# I checked and after loading a few pages, the top-level chrome process
	# may have spawned more child chrome processes, but the chromedriver
	# hasn't spawned any more top-level chromes.
	cd_pid = driver.service.process.pid
	if not cd_pid or type(cd_pid) != int:
		print_error_exit(tag, ("got unexpected cd_pid: {}").format(cd_pid))
	print_debug(tag, ("cd_pid: {}").format(cd_pid))
	children = find_children_of_pid(cd_pid, True,
			"{}/chromedriver".format(outputdir))
	if len(children) != 1:
		print_error(tag, ("expect to get back a single child pid under "
			"cd_pid {}, but find-children returned list {}").format(
			cd_pid, children))
		return (driver, -1)
	chrome_pid = children[0]
	print_debug(tag, ("got top-level chrome_pid {}").format(chrome_pid))

	return (driver, chrome_pid)

# Returns a tuple:
#   (A Selenium webdriver object, or None on error;
#    pid of the browser process).
def start_webdriver(display, which, outputdir):
	tag = 'start_webdriver'

	if which == 'firefox':
		(driver, pid) = start_firefox_webdriver(display)
	elif which == 'chrome':
		(driver, pid) = start_chrome_webdriver(display, outputdir)
	else:
		print_error(tag, ("invalid browser {}").format(which))
		driver = None
		pid = -1

	if driver:
		# Set timeout for page load - I think this is 30 minutes by default,
		# change it to 3 minutes (some page loads for my mediawiki setup
		# do take a while, 1 minute is probably too short...).
		# Note: I haven't explicitly tested this yet, there are some relevant
		# SO questions about this but the documentation sucks and it's
		# not clear this will always/ever work.
		#   http://stackoverflow.com/a/17536547/1230197
		#   http://stackoverflow.com/a/10639332/1230197
		PAGELOAD_TIMEOUT_MINS = 3
		driver.set_page_load_timeout(PAGELOAD_TIMEOUT_MINS * 60)
	
	return (driver, pid)

# Visits every url in the urls list, and takes a checkpoint after each
# visit. If separate_windows is True, the pages will each be loaded in a
# separate window, otherwise the pages will all be loaded in the same
# main window.
# If timeoutsok is set to False, then timeouts when a page fails to
# load (see PAGELOAD_TIMEOUT_MINS in start_webdriver()) will be
# treated as failures, otherwise we'll just move on to the next
# url.
# Returns: 'success' if all visits and checkpoints were performed
#   successfully, 'full' if we exited early due to trace buffer
#   filling up on checkpoints, 'error' on error.
def visit_all_urls(driver, urls, use_separate_windows, tracer,
		which, targetpid=None, timeoutsok=True):
	tag = 'visit_all_urls'

	retcode = 'success'
	take_checkpoints = True
	open_count = 0

	for url in urls:
		if take_checkpoints:
			retcode = tracer.trace_checkpoint("beforevisit-{}".format(url),
					targetpid=targetpid)
			if retcode == 'error':
				break
			elif retcode == 'full':
				# Do we want a full trace buffer to count as a successful
				# run or not? Before adding physical page events, it was
				# possible to visit 30+ URLs without filling up the
				# trace buffer, but with physical page events and a
				# 256 MB per-core buffer it only takes about 10 pages
				# (for Chrome, anyway) before the buffer fills up.
				print_debug(tag, ("trace buffer filled up, ending "
					"trace early").format())
				break
		success = visit_url(driver, url)
		if not success:
			if not timeoutsok:
				print_error(tag, ("visit_url({}) timed out, treating "
					"this as a failure").format(url))
				retcode = 'error'
				break
			else:
				print_warning(tag, ("visit_url({}) timed out, but not "
					"treating this as a failure, will just try next "
					"url").format(url))

		open_count += 1
		if open_count == PATTERN_OPEN:
			print_debug(tag, ("after opening {} tabs/windows, will "
				"now close {} of them").format(PATTERN_OPEN,
				PATTERN_CLOSE))
			open_count = 0
			close_count = 0
			break_outer_loop = False
			while close_count < PATTERN_CLOSE:
				if take_checkpoints:
					retcode = tracer.trace_checkpoint(
						"beforeclose-{}".format(close_count),
						targetpid=targetpid)
					if retcode == 'error':
						break_outer_loop = True
						break
					elif retcode == 'full':
						break_outer_loop = True
						print_debug(tag, ("trace buffer filled up, ending "
							"trace early").format())
						break
				if which == 'firefox':
					success = firefox_close_tab(driver)
					if not success:
						print_error(tag, ("firefox_close_tab() "
							"returned {}").format(success))
						break_outer_loop = True
						retcode = 'error'
						break			
				elif which == 'chrome':
					success = chrome_close_window(driver)
					if not success:
						print_error(tag, ("chrome_close_window() "
							"returned {}").format(success))
						break_outer_loop = True
						retcode = 'error'
						break			
				close_count += 1
			if break_outer_loop:
				print_debug(tag, ("breaking out of outer url "
					"loop"))
				break

		if use_separate_windows and url != urls[-1]:
			# todo: instead of examining which in this method, create
			# a new class that encapsulates driver and its methods
			# that we call for new tab/window, close tab/window,
			# etc.
			if which == 'firefox':
				firefox_create_focus_new_tab(driver)
			elif which == 'chrome':
				success = chrome_create_focus_new_window(driver)
				if not success:
					print_error(tag, ("chrome_create_focus_new_window() "
						"returned {}").format(success))
					retcode = 'error'
					break
			else:
				print_error(tag, ("invalid which {}, not opening "
					"a new window/tab").format(which))

	print_debug(tag, ("returning retcode={}").format(retcode))
	return retcode

# Creates a new tab in the browser and switches focus/control to it.
# Support for tabs in Selenium is very rudimentary, so this method does
# not attempt to return a handle to the new tab or the previous tab or
# anything like that. Unfortunately this method only works for Firefox;
# for Chrome it is just a nop.
# Returns: nothing.
def firefox_create_focus_new_tab(driver):
	tag = 'firefox_create_focus_new_tab'

	# http://stackoverflow.com/a/17558909/1230197
	#   See comment under this answer as well - if you need more
	#   sophisticated tab control, can use something like
	#   "driver.switchTo().window(windowName)".
	body = driver.find_element_by_tag_name("body")
	print_debug(tag, ("Sending ctrl+t to body={}").format(body))
	body.send_keys(Keys.CONTROL + 't')
	# Not necessary:
	# body.send_keys(Keys.CONTROL + Keys.TAB)

	# Ugh, that works great for firefox, but fails for Chrome - try
	# these?
	#   https://stackoverflow.com/questions/6421988/webdriver-open-new-tab
	#   https://stackoverflow.com/questions/10550031/selenium-chromedriver-switch-tabs

	return

# Creates a new window in the current browser and switches focus/control
# to it. This method is somewhat fragile and is possibly not portable
# to non-Linux platforms or to different versions of Chrome.
# This seems to almost work for Firefox, but an error arises on the
# switch_to_window call.
# The reason for this is that Selenium / WebDriver is very lame.
# Returns: True on success, False on error.
def chrome_create_focus_new_window(driver):
	tag = 'chrome_create_focus_new_window'

	# driver is a Selenium WebDriver object; see its API in the file
	# webdriver/remote/webdriver.py.

	pre_num_windows = len(driver.window_handles)
	#print_debug(tag, ("driver.window_handles pre: {} {}").format(
	#	pre_num_windows, driver.window_handles))

	# After messing around with the Selenium / WebDriver / Chromedriver
	# APIs for over an hour on at least two occasions, it seems pretty
	# impossible to easily open a new window or tab in Chrome using
	# the standard APIs. So, here's a solution that appears to work:
	# use the WebDriver to execute a small javascript in the current
	# window that opens a new window, then find and switch to the
	# new window.
	# Don't execute the script synchronously; if anything goes wrong
	# (like the current window was killed before the script could be
	# executed in it), then the execute_script call will never return.
	# Is this solution introducing additional overhead into the application
	# that otherwise would not be there? Yes :( but it doesn't seem like
	# executing a couple lines of javascript is a whole lot of overhead;
	# the URLs that we're visiting are likely to execute waaaay more
	# javascript...
	# This solution is an almagam of these SO solutions:
	#   http://stackoverflow.com/a/9122450/1230197
	#   http://stackoverflow.com/a/11384018/1230197
	#   http://stackoverflow.com/a/10550490/1230197
	new_page_url = 'about:blank'   # seems to work for both FF+Chrome
	script_new_window = (("var newwindow=window.open('{}', "
		"'_blank'); return;").format(new_page_url))
	script_timeout = 5
	driver.set_script_timeout(script_timeout)
	#print_debug(tag, ("executing new window script with timeout "
	#	"{}: {}").format(script_timeout, script_new_window))
	try:
		driver.execute_async_script(script_new_window, [])
		time.sleep(script_timeout)
	except selenium.common.exceptions.TimeoutException:
		# Not sure why this exception always fires, even when the
		# new window appears to open successfully and in a timely
		# manner...
		#print_error(tag, ("TimeoutException fired! Treating this "
		#	"as an error...").format())
		#return False
		print_debug(tag, ("caught TimeoutException, as expected"
			"...").format())
	except selenium.common.exceptions.WebDriverException:
		print_error(tag, ("caught WebDriverException, something "
			"went wrong during script execution (e.g. browser window "
			"was manually switched while running); returning "
			"error").format())
		return False

	post_num_windows = len(driver.window_handles)
	#print_debug(tag, ("driver.window_handles post: {} {}").format(
	#	post_num_windows, driver.window_handles))
	if post_num_windows != pre_num_windows + 1:
		print_error(tag, ("pre_num_windows={}, post_num_windows={}, "
			"but expect it to be {}; returning error").format(
			pre_num_windows, post_num_windows, pre_num_windows + 1))
		return False

	# Ok, once we know that a single new window was opened, we need
	# to make it the current window. In my limited initial executions
	# of this code, it appears that the new window's handle is always
	# appended to the end of the window_handles list (the order of
	# the other window handles in the list is never changed). So,
	# switch to the last name in the list.
	# Ugh: opening the new window in Firefox appears to work, but
	# then when I make this call (with selenium 2.39 and Firefox
	# 26), I get a python traceback ending in "raise BadStatusLine(line)
	# http.client.BadStatusLine: ''". Apparently the Firefox
	# webdriver doesn't like the Command.SWITCH_TO_WINDOW that we
	# send to it.
	#   What to do? Fuck it, use new-tab method for firefox and this
	#   new-window method for chrome.
	driver.switch_to_window(driver.window_handles[-1])
	#print_debug(tag, ("switched to window {}, new blank window "
	#	"should now be focused / current / active").format(
	#	driver.current_window_handle))
	if driver.current_window_handle != driver.window_handles[-1]:
		print_error(tag, ("current window handle doesn't match last "
			"handle in list").format())
		return False

	return True

# Closes the current/active tab.
# Returns: True on success, False on error.
def firefox_close_tab(driver):
	tag = 'firefox_close_tab'

	body = driver.find_element_by_tag_name("body")
	print_debug(tag, ("Sending ctrl+w to body={}").format(body))
	body.send_keys(Keys.CONTROL + 'w')
	time.sleep(2)

	return True

# Closes the current/active Chrome window. After closing the window,
# makes the most-recently-opened window that has not yet been closed
# the active window.
# Returns: True on success, False on error.
def chrome_close_window(driver):
	tag = 'chrome_close_window'

	# driver is a Selenium WebDriver object; see its API in the file
	# webdriver/remote/webdriver.py.

	pre_num_windows = len(driver.window_handles)
	print_debug(tag, ("driver.window_handles pre: {} {}").format(
		pre_num_windows, driver.window_handles))

	try:
		driver.close()
	except Exception as e:
		print_error(tag, ("driver.close() threw some exception, "
			"msg={}. window_handles={}").format(e.msg,
			driver.window_handles))
		return False
	time.sleep(2)

	post_num_windows = len(driver.window_handles)
	print_debug(tag, ("driver.window_handles post: {} {}").format(
		post_num_windows, driver.window_handles))
	if post_num_windows != pre_num_windows - 1:
		print_error(tag, ("pre_num_windows={}, post_num_windows={}, "
			"but expect it to be {}; returning error").format(
			pre_num_windows, post_num_windows, pre_num_windows - 1))
		return False

	# Ok, now make the last remaining window current/active.
	driver.switch_to_window(driver.window_handles[-1])
	print_debug(tag, ("switched to window {}, most-recently-opened "
		"window that hasn't been closed yet "
		"should now be focused / current / active").format(
		driver.current_window_handle))
	if driver.current_window_handle != driver.window_handles[-1]:
		print_error(tag, ("current window handle doesn't match last "
			"handle in list").format())
		return False

	return True

# Returns the list of urls, read from the global browser_urls file.
def get_urls():
	tag = 'get_urls'

	if browser_urls != None:
		try:
			urlfile = open(browser_urls, 'r')
			print_debug(tag, ("opened url file {}").format(browser_urls))
		except:
			urlfile = None
			print_debug(tag, ("couldn't open url file {}, will use default "
				"urls").format(browser_urls))
	else:
		urlfile = None

	if not urlfile:
		urls = default_urls
	else:
		# Read one URL per line:
		urls = []
		line = urlfile.readline()
		while line:
			line = str(line).strip()
			if len(line) > 1 and line[0] != '#':
				urls.append(line)
			line = urlfile.readline()
		urlfile.close()
	return urls

# Returns a tuple:
#   (A browser webdriver, or None on error;
#    the browser's pid;
#    the virtual frame buffer process, or None if not in headless mode).
def start_browser(outputdir, which, use_headless):
	tag = 'start_browser'

	# todo: for Firefox and Chrome (not Mediawiki client), the xvfb
	# events are inside of the trace - could move them outside to
	# shrink trace file size...
	if use_headless:
		(xvfb_p, display) = start_xvfb(outputdir)
		if xvfb_p is None or display is None:
			print_error(tag, ("start_xvfb returned error, driver "
				"not started"))
			return (None, -1, None)
	else:
		(xvfb_p, display) = (None, None)

	(driver, browser_pid) = start_webdriver(display, which, outputdir)
	if not driver or not browser_pid or browser_pid < 2:
		print_error(tag, ("start_webdriver() failed - driver={}, "
			"browser_pid={}").format(driver, browser_pid))
		if driver:
			driver.quit()
		stop_xvfb(xvfb_p)
		return (driver, -1, None)

	return (driver, browser_pid, xvfb_p)

# Should be called after tracing has been turned on.
# Reads urls to navigate to from app_browser_urls.txt; if this file cannot
# be read, uses a set of default URLs.
# Returns a tuple:
#   ('success' on success, 'full' if trace buffer filled, 'error' error;
#    pid of the browser top-level process (may be invalid on error))
def run_browser(outputdir, browser_stdout, browser_stderr, which, tracer):
	tag = 'run_browser'

	success = True

	urls = get_urls()
	print_debug(tag, ("url list: {}").format(urls))

	(driver, browser_pid, xvfb_p) = start_browser(outputdir, which, headless)
	if not driver or not browser_pid or browser_pid < 2:
		print_error(tag, ("start_browser() failed - driver={}, "
			"browser_pid={}").format(driver, browser_pid))
		return (False, -1)

	# Visit each URL in the list:
	retcode = visit_all_urls(driver, urls, SEPARATE_WINDOWS, tracer,
			which, targetpid=browser_pid)
	print_debug(tag, ("got back retcode={} from visit_all_urls, "
		"this will be returned from this method too").format(retcode))

	# .quit() exits the entire browser. To exit a single tab/window,
	# use .close().
	# Uh oh: for some reason, driver.quit() sometimes (always?) fails
	# when using my own firefox built from source with my libs?
	print_debug(tag, ("calling driver.quit()"))
	driver.quit()
	stop_xvfb(xvfb_p)

	return (retcode, browser_pid)

# Performs the following steps:
#   - ...
def browser_init(outputdir):
	tag = 'browser_init'

	browser_stdout_fname  = "{}/browser-stdout".format(outputdir)
	browser_stderr_fname  = "{}/browser-stderr".format(outputdir)
	browser_stdout  = open(browser_stdout_fname, 'w')
	browser_stderr  = open(browser_stderr_fname, 'w')

	return (browser_stdout, browser_stderr)

def browser_cleanup(files_to_close):
	close_files(files_to_close)
	return

def browser_exec(outputdir, which):
	tag = 'browser_exec'

	if which not in valid_browsers:
		print_error(tag, ("invalid browser: {}").format(which))
		return []

	#print_debug(tag, ("os.environ: {}").format(os.environ))

	# The output_dir already distinguishes between firefox and chrome.
	(browser_stdout, browser_stderr) = browser_init(outputdir)
	target_pids = []
	tracer = traceinfo(which)

	success = tracer.trace_on(outputdir,
			descr="starting browser {}".format(which))
	if success:
		(retcode, browser_pid) = run_browser(outputdir,
				browser_stdout, browser_stderr, which, tracer)
		if retcode == 'success':
			success = True
		else:
			print_error(tag, ("run_browser() returned {}, considering "
				"this an error here. echo {} > target_pids to "
				"analyze trace anyway").format(retcode, browser_pid))
			success = False
	(tracesuccess, buffer_full) = tracer.trace_off(
			descr="{} complete".format(which), targetpid=browser_pid)
	if retcode == 'full':   # checkpoints from inside run_browser()
		buffer_full = True
	#print_debug(tag, ("os.environ: {}").format(os.environ))

	if success:
		if not tracesuccess:
			print_error(tag, ("tracesuccess is false, returning "
				"error").format())
			success = False
			target_pids = []
		elif buffer_full:
			print_error(tag, ("trace buffer filled up; still considered "
				"an error for now, but if you want to, echo {} > "
				"target_pids file to analyze trace anyway").format(
				browser_pid))
			success = False
			target_pids = []
		else:
			print_debug(tag, ("").format(buffer_full))
			target_pids.append(browser_pid)
	else:
		print_error(tag, ("trace_on() or run_browser() returned failure; "
			"will just clean up and return now. target_pids will be "
			"empty, but echo {} > target_pids file to analyze "
			"trace anyway").format(browser_pid))

	browser_cleanup([browser_stdout, browser_stderr])

	return target_pids

def firefox_exec(outputdir):
	return browser_exec(outputdir, 'firefox')

def chrome_exec(outputdir):
	return browser_exec(outputdir, 'chrome')

# First arg is "appname" member: used to construct output directory.
firefox_app = app_to_run('ffox', firefox_exec)
chrome_app = app_to_run('chrome', chrome_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
