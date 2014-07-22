# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Automation script for LibreOffice.
#
# Currently workload: opens an empty document in Writer, types 50 KB of
# text into it, saves it, and exits.
# 
# Setup steps: perform these once (not automated by this script)
#   Ensure that libreoffice_bin is set correctly in system_conf.py
#   Ensure that other commands and directories below are set correctly.
#   Ensure that xdotool is installed and is in your PATH.
#   ...
#  - FIRST: run this once manually and make sure that if a prompt comes
#    up asking you if you'd like to save in openoffice format instead
#    of microsoft format, then you check the box to disable this box
#    from appearing again (during automatic execution of this script)!

from app_scripts.app_to_run_class import *
from trace.run_common import *
from trace.traceinfo_class import traceinfo
from util.pjh_utils import *

# Run Office in a virtual X frame buffer, or attempt to start Office
# instance normally? Note: if run in non-headless mode over ssh with
# X forwarding, this script will execute much more slowly - recommended
# to run locally if non-headless.
headless = True

office_dir = "{}/libreoffice".format(apps_dir)
empty_doc = "{}/empty-doc.docx".format(office_dir)
working_doc = "{}/working-doc.docx".format(office_dir)
input_text = "{}/shakespeare-50K.txt".format(office_dir)

office_flags = '--nologo --norestore --nofirststartwizard'
writer_flags = '--writer'
calc_flags   = '--calc'

#poll_period = 0
poll_period = 10

##############################################################################

# If display is not None, the environment variable DISPLAY=display will
# be set before starting LibreOffice and sending xdotool commands to
# it. For headless operation, the display argument should be set to
# what was returned from start_xvfb().
# Should be called after tracing has been turned on.
# Returns a tuple:
#   (True on success, False on error;
#    pid of the office process (may be invalid on error))
def run_office(outputdir, office_stdout, office_stderr, display, tracer):
	tag = 'run_office'

	env = os.environ.copy()
	if display:
		env['DISPLAY'] = display
		print_debug(tag, ("set env['DISPLAY']={}").format(env['DISPLAY']))

	# Check if there are already any 'soffice' processes
	# running; if there are, then this method will fail to work as
	# expected, because the command to execute soffice will just be
	# redirected to the already-running process and it may not have
	# the initial state that we expect it to be in.
	cmd = 'pgrep soffice'
	(retcode, out, err) = exec_cmd_get_output(cmd)
	if retcode == 0 or len(out) > 0:
		# when pgrep finds nothing, its retcode should be 1
		print_error(tag, ("\"pgrep soffice\" returned code {} and "
			"output {} - there are already office processes running, "
			"so this method will fail! Returning error now.").format(
			retcode, out))
		return (False, -1)

	# Workload flow:
	#   Remove old "work" document
	#   Copy empty document to work document
	#   Start office, opening work document
	#   Use xdotool to "type" target text file into work document
	#   Save work document
	#   Use xdotool to close office
	try:
		os.remove(working_doc)
	except:
		# Ignore exceptions, probably / hopefully just means that old
		# doc not present.
		pass

	print_debug(tag, ("copying empty doc {} to working-doc {}").format(
		empty_doc, working_doc))
	try:
		shutil.copyfile(empty_doc, working_doc)
	except:
		print_error(tag, ("copyfile {} {} failed, returning now").format(
			empty_doc, working_doc))
		return (False, -1)

	# Start the office process, making sure to specify our env variable
	# dict, which may include a headless DISPLAY.
	cmd = "{} {} {} -o {}".format(libreoffice_bin, office_flags,
			writer_flags, working_doc)
	print_debug(tag, ("constructed cmd=\"{}\"").format(cmd))
	args = shlex.split(cmd)
	office_p = subprocess.Popen(args, stdout=office_stdout,
			stderr=office_stderr, env=env)
	if not office_p:
		print_error(tag, ("Popen returned None; cmd={}").format(cmd))
		return (False, -1)

	# Important: we must wait a little while here, otherwise the
	# following xdotool command won't see the X window because it
	# hasn't actually popped up yet.
	WAITTIME = 10
	print_debug(tag, ("started office process with pid {}, will wait "
		"{} seconds for it to start up").format(office_p.pid, WAITTIME))
	time.sleep(WAITTIME)

	# To interact with the office window, we use xdotool(1). It's a
	# little hairy sometimes but it gets the job done.
	#   If xdotool can't get the job done, perhaps "Xnee" can:
	#   https://www.gnu.org/software/xnee/
	# First we need to run a command to get a handle for the office
	# window. Then, we run another command to take the input file
	# and "type" it into the office window. It should be possible to
	# do this in a single xdotool command, but unfortunately it looks
	# like xdotool's type command doesn't work properly with its
	# "command chaining" feature. Dammit.
	# Also, it's important that we specify the same display to xdotool
	# that we do to office, or else xdotool will fail!
	windowtitle = 'LibreOffice Writer'
	handle = xdotool_get_window_handle(windowtitle, env)
	if handle is None:
		print_error(tag, ("failed to get X window handle, killing "
			"office process and returning error"))
		kill_Popens([office_p])  # this DOES work on office process
		return (False, -1)
	elif handle is -1:
		print_error(tag, ("no X windows found matching title {}, "
			"killing office process and returning error").format(
			windowtitle))
		kill_Popens([office_p])
		return (False, -1)

	# Use xdotool to "type" text into the window whose handle we just
	# got. The critical parameter here is the delay (in ms): a delay too
	# large will make this script take longer than it needs to, but a
	# delay too small will cause some kind of buffering weirdness in
	# LibreOffice and the display won't be able to keep up with the
	# incoming text, causing significant lag + delay. The sweet spot
	# seems to be 4-6 ms - anything less than that is a bad idea.
	# To type in 50 KB of text, this command should take up to 3 minutes;
	# so, we might as well trace_wait() while it's running.
	# Important: to get this working, I needed to make sure to NOT use
	# shell=True in Popen, and to use the -a flag with xargs rather than
	# trying to read the text from stdin. If I tried other ways, xdotool
	# would appear to be running but nothing would be typed, presumably
	# because of some weird shell / xargs interaction.
	# NOTE: if testing this script over ssh -X, the office window will
	# accept input from the xdotool command much more slowly; even
	# with a delay of 10, the xdotool command still completes 90 seconds
	# before the text finishes in the office window. Running while
	# logged in directly to the machine is recommended.
	delay = 6
	cmd = ("xargs -a {} -0 xdotool type --window {} --delay {} "
			"--clearmodifiers ").format(input_text, handle, delay)
	print_debug(tag, ("constructed cmd=\"{}\"").format(cmd))
	args = shlex.split(cmd)
	xdotool_p = subprocess.Popen(args, env=env)  # todo: set stderr, stdout
	if not xdotool_p:
		kill_Popens([office_p])  # this DOES work on office process
		print_error(tag, ("Popen returned None; cmd={}").format(cmd))
		return (False, -1)

	if not tracer.perf_on():
		print_error(tag, ("perf_on() failed, but continuing"))
	prefix = 'xdotool'
	retcode = tracer.trace_wait(xdotool_p, poll_period, prefix,
			targetpid=office_p.pid)
	tracer.perf_off()

	if retcode == 'error' or retcode == 'full':
		# Don't expect trace buffer to fill up during this application;
		# count this as an error.
		print_error(tag, ("trace_wait() returned {}; xdotool's "
			"returncode is {}. Will terminate processes and "
			"return error here").format(retcode, xdotool_p.returncode))
		kill_Popens([xdotool_p, office_p])
		return (False, -1)
	elif xdotool_p.returncode is None:
		print_error(tag, ("xdotool process' returncode not set?!?").format())
		kill_Popens([xdotool_p, office_p])
		return (False, -1)
	elif xdotool_p.returncode != 0:
		print_error(tag, ("xdotool process returned error {}").format(
			xdotool_p.returncode))
		kill_Popens([office_p])
		return (False, -1)

	# Ok, last two steps: save the document, then close the office app.
	# Both of these can be accomplished with simple keystroke combinations
	# sent via xdotool. However, a few notes:
	#  - FIRST: run this once manually and make sure that if a prompt comes
	#    up asking you if you'd like to save in openoffice format instead
	#    of microsoft format, then you check the box to disable this box
	#    from appearing again (during automatic execution of this script)!
	#  - Put a little delay between these keystrokes, especially BEFORE
	#    the first one, so that we can be absolutely sure the text input
	#    is complete. Without this delay, the ctrl+s can get missed.
	#  - It's important that we open LibreOffice into the "working
	#    document" above, rather than using a new document - it means
	#    that when we hit ctrl+s here, the document should be saved
	#    without any prompts.
	#  - To close LibreOffice Writer in the normal case, ctrl+q seems to
	#    work well, and alt+F4 doesn't really seem to work.
	cmds = []
	cmd = ("xdotool key --window {} --clearmodifiers ctrl+s").format(
			handle)
	cmds.append(cmd)
	#cmd = ("xdotool key --window {} --clearmodifiers KP_Enter").format(
	#		handle)  # to be safe if any additional dialogs pop up
	#  # (this was a bad idea - can't do this after saving, or you'll
	#  #  need to save again!)
	#cmds.append(cmd)
	cmd = ("xdotool key --window {} --clearmodifiers ctrl+q").format(
			handle)
	cmds.append(cmd)
	for cmd in cmds:
		time.sleep(WAITTIME)
		print_debug(tag, ("executing cmd=\"{}\"").format(cmd))
		args = shlex.split(cmd)
		retcode = subprocess.call(args, env=env)
		if retcode != 0:
			print_error(tag, ("call({}) returned error, will continue "
				"on").format(cmd))

	# Finally, check that the office process terminated.
	# In one execution, waiting 15 seconds here was not enough...
	waittimeout = 20
	print_debug(tag, ("waiting up to {} seconds for office process "
		"to complete").format(waittimeout))
	try:
		office_p.wait(timeout=waittimeout)
	except subprocess.TimeoutExpired:
		# To handle this a little more cleanly, we could check for a
		# window with title "Save document", which would indicate that
		# the save didn't work as expected and we're being prompted to
		# save our changes... but for now, just terminate the process
		# forcefully (I tested this and it should work, even if office
		# has popped up other dialogs that it wants us to answer).
		print_error(tag, ("office process {} hasn't terminated "
			"yet, will try to kill it").format(office_p.pid))
		kill_Popens([office_p])
		return (False, -1)

	if office_p.returncode != 0:
		print_error(tag, ("office process terminated with non-zero "
			"returncode {} - returning error here").format(
			office_p.returncode))
		return (False, -1)
	print_debug(tag, ("office process terminated successfully, "
		"returning its pid {}").format(office_p.pid))

	return (True, office_p.pid)

def office_cleanup(files_to_close):
	close_files(files_to_close)
	return

def office_exec(outputdir):
	tag = 'office_exec'

	(office_stdout, office_stderr) = new_out_err_files(outputdir, 'office')
	target_pids = []
	tracer = traceinfo('office')

	# Start+stop the X virtual frame buffer outside of the trace.
	if headless:
		(xvfb_p, display) = start_xvfb(outputdir)
		if xvfb_p is None or display is None:
			print_error(tag, ("start_xvfb returned error, returning "
				"[] without starting office"))
			return []
	else:
		(xvfb_p, display) = (None, None)

	success = tracer.trace_on(outputdir, descr="starting LibreOffice".format())
	if success:
		(success, office_pid) = run_office(outputdir, office_stdout,
				office_stderr, display, tracer)
	(tracesuccess, buffer_full) = tracer.trace_off(
			descr="LibreOffice complete".format())

	if success:
		if not tracesuccess or buffer_full:
			print_error(tag, ("trace buffer filled up before "
				"tracing turned off - considering this an error "
				"here").format())
			success = False
			target_pids = []
		else:
			target_pids.append(office_pid)
	else:
		print_error(tag, ("trace_on() or run_office() returned failure; "
			"will just clean up and return now. target_pids will be "
			"empty...").format())

	if headless:
		stop_xvfb(xvfb_p)
	office_cleanup([office_stdout, office_stderr])

	return target_pids

# First arg is "appname" member: used to construct output directory.
office_app = app_to_run('office', office_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
