# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from trace.run_common import *
from util.pjh_utils import *

maxnamelen = 0

# app_to_run defines methods that will differ per-application. Common
# methods that all apps will end up calling (e.g. for checkpointing) are
# in run_common.py.

class app_to_run:
	tag = 'app_to_run'

	# Members:
	#   appname: name of the application being run...
	#   execfn:
	#     Signature: execfn(outputdir) returns [pids]
	#     This method is passed a directory where all output files should
	#     be written. The method should return a list of "target pids":
	#     the top-level pids that we care about for analysis purposes.
	#     These pids will be written to a special file that will be read
	#     during the analysis and plot-generation phases. Typically, the
	#     execfn method will only need to return a single pid, for the
	#     application process that it started; the trace analysis will
	#     then automatically group together all of the child processes
	#     that start from this target pid.
	#       Tip: when a Popen object has been created using
	#       subprocess.Popen(), its pid can be gotten by simply using .pid.
	#       Don't just use subprocess.call() to run apps, since this method
	#       doesn't allow the pid to be retrieved.
	#       http://docs.python.org/3/library/subprocess.html?highlight=subprocess#subprocess.Popen.pid
	appname = None
	execfn = None

	def __init__(self, appname, execfn):
		tag = "{}.__init__".format(self.tag)

		if (not appname or not execfn):
			print_error_exit(tag, ("None argument: appname={}, "
				"execfn={}").format(appname, execfn))

		self.tag += ".{}".format(appname)
		if maxnamelen > 0 and len(appname) > maxnamelen:
			appname = appname[0:maxnamelen]
		self.appname = appname
		self.execfn = execfn

		return

	# Returns: True if at least one target_pid was returned and
	# saved, or False on error.
	def execute(self, outputdir):
		tag = "{}.execute".format(self.tag)

		success = True

		print_debug(tag, ("entered, calling self.execfn()").format())
		target_pids = self.execfn(outputdir)

		if target_pids and len(target_pids) > 0:
			print_debug(tag, ("got back target_pids: {}").format(
				target_pids))
			write_target_pids(outputdir, target_pids)
		else:
			# For "manual" app execution, we may hit this case if the user
			# didn't explicitly input any target pids.
			print_unexpected(False, tag, ("got back empty target_pids "
				"list from {}, will write an error marker into "
				"{}").format(self.appname, outputdir))
			write_error_marker(outputdir, "empty target_pids list returned")
			success = False

		return success

if __name__ == '__main__':
	print_error_exit("not an executable module")
