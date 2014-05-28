#! /usr/bin/env python3.3

# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from conf.applist import *
from trace.run_common import *
from conf.system_conf import *
from util.pjh_utils import *
import trace.vm_common as vm
import argparse
import datetime
import os
import random
import re
import shlex
import shutil
import subprocess
import sys


##############################################################################
def run_app(app, app_output_dir):
	tag = 'run_app'

	print_debug(tag, ("calling execute() for app.appname={}").format(
		app.appname))
	success = app.execute(app_output_dir)

	return success

def init_per_app(app, output_dir):
	tag = 'init_per_app'
	
	app_output_dir=("{0}/{1}").format(output_dir, app.appname)

	if os.path.exists(app_output_dir):
		print_error_exit(tag, ("app output directory \'{}\' already "
			"exists").format(app_output_dir))
	else:
		os.mkdir(app_output_dir)
		print_debug(tag, ("created new app output dir: {}").format(
			app_output_dir))

	return app_output_dir

def cleanup_per_app(app, app_output_dir):
	tag = 'cleanup_per_app'

	return

def init_global(results_subdir):
	tag = 'init_global'

	now = datetime.datetime.now().strftime("%Y%m%d-%H.%M.%S")

	if results_subdir:
		results_dir = "{}/{}".format(RUN_OUTDIR, results_subdir)
		link = results_subdir
	else:
		results_dir=("{}/{}").format(RUN_OUTDIR, now)
		link = now

	if os.path.exists(results_dir):
		print_error(tag, ("Output directory \'{}\' already exists").format(
			results_dir))
		return None
	os.makedirs(results_dir)
	
	print('Output will be saved in directory {}'.format(results_dir))

	try:
		os.unlink(latest_linkdir)
	except OSError:
		pass
	os.symlink(link, latest_linkdir)

	return results_dir

def cleanup_global(output_dir):
	return

#def usage():
#	print(("usage: {0}").format(sys.argv[0]))
#	print(("  will create output in a subdir under {}").format(RUN_OUTDIR))
#	print(("  current applist: {}").format(run_applist_str()))
#	sys.exit(1)

def handle_args():
	tag = 'handle_args'

	descr = ("Runs the applications in the applist.\n\tCurrent "
			"applist: {}").format(run_applist_str())
	run_name_help = ("name of this run - if specified, results "
			"will be saved in a subdirectory of {} with this "
			"name").format(RUN_OUTDIR)

	# http://docs.python.org/3/library/argparse.html
	parser = argparse.ArgumentParser(description=descr)
	parser.add_argument('results_subdir', metavar='run_name',
			type=str, nargs='?', default=None,
			help=run_name_help)

	args = parser.parse_args()   # uses sys.argv
	print_debug(tag, ("parser returned args: {}").format(args))

	return (args.results_subdir)

##############################################################################
# Main:
if __name__ == '__main__':
	tag = 'main'

	failed_apps = []

	(results_subdir) = handle_args()
	output_dir = init_global(results_subdir)
	if not output_dir:
		print_error(tag, "exiting without running")
		sys.exit(1)

	randomize = True  # todo: add command-line arg for this
	if randomize:
		apps = list(run_applist)
		random.shuffle(apps)
	else:
		apps = run_applist

	for app in apps:
		app_output_dir = init_per_app(app, output_dir)
		success = run_app(app, app_output_dir)
		if not success:
			failed_apps.append(app.appname)
		cleanup_per_app(app, app_output_dir)
	cleanup_global(output_dir)

	if len(failed_apps) > 0:
		print_error(tag, ("Execution failed for the following apps: "
			"{}\nThey may have some trace data, but no target_pids "
			"were returned due to some error.").format(failed_apps))

	sys.exit(0)
else:
	print('Must run stand-alone')
	usage()
	sys.exit(1)
