# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

import argparse
from trace.run_common import *

# http://docs.python.org/3/library/argparse.html
# http://docs.python.org/3/library/argparse.html#parents
# Parent parser must be initialized before child parsers.

common_analysis_parser = argparse.ArgumentParser(
		description=("Common arguments for trace file analysis"),
		add_help=False)
common_analysis_parser.add_argument('-ng', '--no-group',
		action='store_false', default=True, dest='group_multiproc',
		help=("don't group stats together for multiprocess apps "
			"started during trace"))
common_analysis_parser.add_argument('-u', '--userstacks',
		action='store_true', default=False, dest='process_userstacks',
		help=("process user stack traces in trace events file"))
common_analysis_parser.add_argument('-f', '--functions',
		action='store_true', default=False, dest='lookup_fns',
		help=("enable lookup of userstacktrace functions"))
common_analysis_parser.add_argument('-np', '--no-page',
		action='store_true', default=False, dest='skip_page_events',
		help=("skip physical page events"))

plots_parser = argparse.ArgumentParser(
		parents=[common_analysis_parser],
		description=("Analyzes the kernel trace files from a measurement "
			"run and generates multi-app plots"))
plots_parser.add_argument('measurementdir', metavar='measurement-dir',
		type=str, nargs='?', default=latest_linkdir,
		help=("directory containing trace measurement results from "
			"run_apps.py (default: {})").format(latest_linkdir))

analyze_parser = argparse.ArgumentParser(
		parents=[common_analysis_parser],
		description=("Analyzes a kernel trace file with vma "
			"operation events"))
analyze_parser.add_argument('trace_fname',
		metavar='trace-events-file', type=str,
		help='output from /sys/kernel/debug/tracing/trace')
analyze_parser.add_argument('outputdir',
		metavar='output-dir', type=str,
		help=("directory to write output files to; will be created or "
			"overwritten"))
analyze_parser.add_argument('-a', '--app',
		metavar='appname', type=str, default='app', dest='appname',
		help=("name of application, to setup output dirs"))
analyze_parser.add_argument('-p',
		metavar='target-pids', type=str, default=None, dest='target_pids',
		help=("file containing target pids"))

sum_vm_parser = argparse.ArgumentParser(
		description=("Adds up the virtual memory size of all of "
			"the vmas in a maps or smaps file")
		)
sum_vm_parser.add_argument('maps_fname',
		metavar='mapsfile', type=str,
		help='maps (or smaps) file')

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)

