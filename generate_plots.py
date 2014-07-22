#! /usr/bin/env python3.3

# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from analyze.argparsers import *
from trace.run_common import *
from util.pjh_utils import *
from analyze.process_group_class import *
from conf.system_conf import *
from analyze.vm_mapping_class import *
import plotting.multiapp_plot_class as multiapp_plot
import conf.PlotList as PlotList
import plotting.plots_common as plots
import trace.traceinfo_class as traceinfo

# Globals:

##############################################################################

# Returns a list of the analysis results directories ("analysisdirname"
# from run_common.py) found found in the specified measurement
# directory. These directories are likely actually created earlier in
# this script's execution, but using this method to find the desired
# directories should be a bit more robust / flexible.
def find_analysis_dirs(measurementdir):
	tag = 'find_analysis_dirs'

	analysisdirs = find_files_dirs(measurementdir, analysisdirname,
			exactmatch=True, findfiles=False, finddirs=True,
			followlinks=True, absdirs=True)
	print_debug(tag, ("got back from find_files_dirs({}, {}): "
		"{}").format(measurementdir, analysisdirname, analysisdirs))

	return analysisdirs

# This method performs the following steps:
#   Searches the subdirectories of the measurementdir for file names
#   that exactly match target_fname.
#   Passes those files to the specified analysis_method, which will
#   write outputfiles into the specified analysis_dirname
# Returns: a list of all of the plots generated during the analysis runs.
def analyze_apps(measurementdir, target_fname, analysis_method,
		group_multiproc, process_userstacks, lookup_fns, skip_page_events):
	tag = 'analyze_apps'

	plotlist = []

	# target_fname: caller should pass tracefilename or PERF_DATA.
	targetfiles = find_files_dirs(measurementdir, target_fname,
			exactmatch=True, findfiles=True, finddirs=False,
			followlinks=True, absdirs=True)
	print_debug(tag, ("got back targetfiles from find_files_dirs({}, "
		"{}): {}").format(measurementdir, target_fname, targetfiles))
	for fname in targetfiles:
		# For outputdir, use root dir plus a well-known suffix. Also,
		# we can take the name of the directory that contains the
		# tracefile as the application name - the run_apps.py
		# script should ensure this. Look for a target_pids file
		# next to the target_fname file.
		appdir = os.path.dirname(fname)
		appname = os.path.basename(appdir)
		target_pids = read_target_pids(appdir)
		if len(target_pids) == 0:
			print_error(tag, ("empty target_pids list "
				"returned for appdir {}, will skip to next target "
				"file").format(appdir))
			continue

		newplots = analysis_method(fname, appdir, group_multiproc,
				process_userstacks, lookup_fns, target_pids,
				appname, skip_page_events)
		plotlist += newplots
		print_debug(tag, ("plotlist for this phase now contains {} "
			"plots").format(len(plotlist)))

	return plotlist

# Looks in all of the subdirectories of the measurementdir and generates
# plots that include all apps that have an analysis directory.
def plot_apps_in_measurementdir(measurementdir, allplots):
	tag = 'plot_apps_in_measurementdir'

	# analysis_plotlist was used in analyze_trace.py (which we called
	# earlier from this script via analyze.analyze_main()): every
	# multiapp_plot object in the plotlist had series + datapoints
	# added to it, then those series were serialized into files:
	#   app1dir/plotdir/series001.dat
	#   app1dir/plotdir/series002.dat
	#   app2dir/plotdir/series001.dat
	#   app2dir/plotdir/series002.dat
	#   ...
	# Where app1dir, app2dir, etc. come from find_analysis_dirs() below.
	# 
	# Now, here in generate_plots.py, we want to use the same
	# analysis_plotlist again. The workingdirs for the plot objects
	# will be set to the workingdirs for the last application that
	# was analyzed; now, we need to reset the plot object (to clear
	# out any series from the last-analyzed app), then set the workingdir
	# for each plot object to the top-level measurementdir (which will
	# create a new subdir for each plot), deserialize the data that
	# was output during the analysis run (found in the appdirs that
	# come from find_analysis_dirs()), and finally "complete" each
	# plot object to create the plots.
	plotdir = "{}/plots".format(measurementdir)
	if not os.path.exists(plotdir):
		os.mkdir(plotdir)
	plots_pdf = plots.new_pdffile("{}/allplots".format(plotdir))
	#pdf_fname = "{}/allplots.pdf".format(plotdir)
	#print_debug(tag, ("using pdffile: {}").format(pdf_fname))

	plotlist = multiapp_plot.remove_duplicates_from_plotlist(allplots)

	for plot in plotlist:
		plot.reset()
		plot.add_pdffile(plots_pdf)
		plot.set_workingdir(plotdir)  # appends plot title to plotdir
		print_debug(tag, ("expect this plot to be output in workingdir "
			"{}").format(plot.workingdir))

	# Better way: for each plot, search for directories in the measurementdir
	# with the name of the plot, and look for data files only in those
	# directories. Doesn't rely on specific link between plots generated
	# by a particular analysis (e.g. "generate-analysis" and "perf-reports"),
	# but uses more "find" operations and will be slower. Also note that
	# this command may find some dirs (e.g. the dirs created for storing
	# the plot figures themselves) that won't contain series .dat files;
	# this is ok.
	#   If the speed really becomes a problem, store an explicit link
	#   earlier from the plot to the directory name (e.g. "perf-reports")
	#   where we expect to find its data files.
	for plot in plotlist:
		plotdata_dirs = find_files_dirs(measurementdir, plot.plotname,
				exactmatch=True, findfiles=False, finddirs=True,
				followlinks=True, absdirs=True)
		print_debug(tag, ("plotdata_dirs: {}").format(plotdata_dirs))

		for d in plotdata_dirs:
			plot.deserialize(d)

		print_debug(tag, ("completing plot: {}").format(plot))
		plot.complete()
	
	plots.close_pdffile(plots_pdf)

	return

def handle_args():
	tag = 'handle_args'

	parser = plots_parser
	parser.add_argument('-a', '--no-analyze',
		action='store_false', default=True, dest='analyze_first',
		help=("skip analysis, build plots using data already in "
			"measurementdir"))
	parser.add_argument('-p', '--no-perf-analysis',
		action='store_false', default=True, dest='analyze_perf',
		help=("skip perf analysis, build plots using data already in "
			"measurementdir"))

	args = parser.parse_args()   # uses sys.argv
	print_debug(tag, ("parser returned args: {}").format(args))
	
	if not os.path.exists(args.measurementdir):
		print_error(tag, ("non-existent measurementdir: {}").format(
			args.measurementdir))
		return (None, None, None, None, None, None)

	return (args.measurementdir, args.group_multiproc,
		args.process_userstacks, args.lookup_fns,
		args.analyze_first, args.analyze_perf,
		args.skip_page_events)

##############################################################################
# Main:
if __name__ == '__main__':
	tag = 'main'

	(measurementdir, group_multiproc, process_userstacks,
		lookup_fns, analyze_first, analyze_perf,
		skip_page_events) = handle_args()
	if not measurementdir:
		print("exiting")
		sys.exit(1)

	# Keep track of the plots generated during the analysis runs.
	allplots = []

	if analyze_first:
		import analyze_trace as analyze
		newplots = analyze_apps(measurementdir, traceinfo.tracefilename,
				analyze.analyze_main, group_multiproc,
				process_userstacks, lookup_fns, skip_page_events)
		allplots += newplots
	else:
		print("Skipping analysis, using data already in {} and using "
				"plots listed in analysis_plotlist".format(measurementdir))
		allplots += PlotList.analysis_plotlist
	
	if analyze_perf:
		import analyze.perf_analysis as perf_analysis
		newplots = analyze_apps(measurementdir, traceinfo.PERF_DATA,
				perf_analysis.perf_main, group_multiproc,
				process_userstacks, lookup_fns, skip_page_events)
		allplots += newplots
	else:
		print("Skipping perf analysis, using data already in {}".format(
			measurementdir))
		# crap: plot objects are dynamically generated during perf analysis
		#   todo: create a default list of perf plots so that they can be
		#   added to allplots here?
	
	plot_apps_in_measurementdir(measurementdir, allplots)
	print("Plot generation complete, see plot subdirs under {}".format(
		measurementdir))

	sys.exit(0)
else:
	print('Must run stand-alone')
	sys.exit(1)
