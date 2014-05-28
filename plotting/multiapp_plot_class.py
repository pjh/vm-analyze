# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
from plotting.PlotEvent import PlotEvent
import plotting.plots_common as plots
import pickle
import re

SERIESPREFIX = 'series'
SERIESSUFFIX = 'dat'
NOAPPNAME = 'noapp'

'''
Identifies one series of data for a multiapp_plot. A series object is
intended to be very simple: just a name and a list of opaque
tuples for datapoints. It is up to each different multiapp_plot object
to interpret these datapoints.
'''
class series:
	tag = 'series'

	seriesname = None
	appname = None
	data = None

	def __init__(self, seriesname, appname):
		tag = "{}.__init__".format(self.tag)

		# be careful: we do allow seriesnames to be ints...
		if (not seriesname or
			(type(seriesname) == str and len(seriesname) < 2) or
		    not appname or
			(type(appname) == str and len(appname) < 2)):
			print_error_exit(tag, ("invalid arg: seriesname={}, "
				"appname={}").format(seriesname, appname))

		self.seriesname = seriesname
		self.appname = appname
		self.data = list()
		return

	def append_datapoint(self, datapoint):
		self.data.append(datapoint)
		return True

	# Optional sortkey: something like "lambda datapoint: datapoint[0]"
	def data(self, sortkey=None):
		if sortkey:
			return sorted(self.data, key=sortkey)
		return self.data

	def serialize(self, outputfname):
		tag = "{}.serialize".format(self.tag)

		# It should be very simple to use Python's "pickle" module
		# to write the opaque tuples in the datapoint list to the
		# output file. The only potential drawback is that this data
		# is in a binary format by default, and will not be readable
		# by a human or e.g. Excel. If we'd like to write out CSV/TSV
		# files for use in Excel, this can be added here later by
		# adding a method to write out the data in that format, or
		# possibly by using protocol version 0 for the pickle module.
		# 
		# http://docs.python.org/3/library/pickle.html#module-pickle
		# http://docs.python.org/3/library/pickle.html#pickle.dump

		print_debug(tag, ("pickling {} self.data points for series "
			"{} and app {} to file {}").format(len(self.data),
			self.seriesname, self.appname, outputfname))
		f = open(outputfname, 'wb')  # binary mode!
		# http://stackoverflow.com/a/2842727/1230197
		pickle.dump(self.__dict__, f, protocol=pickle.DEFAULT_PROTOCOL)
		f.close()

		return

	# Returns: True on success, False on error.
	def deserialize(self, inputfname):
		tag = "{}.deserialize".format(self.tag)

		# See pickling comments in serialize() above...
		# http://docs.python.org/3/library/pickle.html#module-pickle

		if len(self.data) != 0:
			print_error(tag, ("self.data already has {} datapoints "
				"in it!").format(len(self.data)))
			return False

		f = open(inputfname, 'rb')  # binary mode!
		# http://stackoverflow.com/a/2842727/1230197
		tmp_dict = pickle.load(f)
		self.__dict__.update(tmp_dict)
		f.close()

		print_debug(tag, ("unpickle successful: appname={}, "
			"seriesname={}, self.data contains {} "
			"datapoints").format(self.appname, self.seriesname,
			len(self.data)))
		return True

##############################################################################
'''
Class with high-level methods for creating a plot with multiple series
for multiple applications. Each instance of this class will define its
own method for creating a plot, but the directory structure, file naming,
etc. is controlled here to remain consistent across all plots.
The datapoints stored in instances of this class are opaque tuples - only
the plotting function knows how to interpret them.
'''
class multiapp_plot:
	tag = 'multiapp_plot'

	# These stay constant across reset()s:
	plotname = None
	plotfn = None
	datafn = None

	# These are reset on a reset() call:
	workingdir = None
	currentapp = None
	seriesdict = None
	auxdata = None
	pdffiles = None

	# Arguments:
	# auxdataclass
	#   Class name for auxiliary data that this plot needs to keep track
	#   of (e.g. a running total of vmas). multiapp_plot knows nothing
	#   about this class and never calls any methods on it, but will
	#   instantiate a new object of this class for each new multiapp_plot
	#   object. This will ensure that even if multiple plots share a
	#   datafn or plotfn, they won't share any auxiliary / global data.
	# def plotfn(auxdata, seriesdict, plotname, workingdir)
	#   seriesdict is a dictionary mapping series seriesnames to their
	#   series objects. The plotfn should not save the plot to the
	#   workingdir itself, but the workingdir is passed in case the
	#   plot wants to write out any other data (e.g. a table).
	#   Returns: plotfig, a matplotlib Figure object for the plot.
	# def datafn(auxdata, plot_event, tgid, currentapp)
	#   plot_event: a PlotEvent from the analysis script...
	#   tgid: the tgid that this vma / event is being attributed to
	#     (determined by the method that calls consume_plot_event()).
	#   currentapp: the app that this vma / event is being attributed to.
	#   Returns: a list of tuples: (seriesname, datapoint), where
	#     datapoint is an opaque item that will be appended to the
	#     specified series' list of datapoints. The plotfn is what
	#     needs to understand these datapoints.
	# def processfn(auxdata, active_vmas, appname, app_pid)
	#   Processes the list of active_vmas from a specific point-in-time
	#   during the trace. Should return a list of PlotEvent objects,
	#   which will then be passed to the datafn (via consume_plot_event).
	#   Returns: a list of PlotEvent objects.
	# def resetfn(auxdata)
	#   ...
	def __init__(self, plotname, auxdataclass, plotfn, datafn, resetfn,
			processfn=None):
		tag = "{}.__init__".format(self.tag)

		if not plotname or len(plotname) < 2:
			print_error_exit(tag, ("invalid plotname {}").format(plotname))
		if not plotfn:
			print_error_exit(tag, ("plotfn is None!"))
		if not datafn:
			print_error_exit(tag, ("datafn is None!"))
		if not resetfn:
			print_error_exit(tag, ("resetfn is None!"))

		self.plotname = plotname
		self.plotfn = plotfn
		self.datafn = datafn
		self.resetfn = resetfn
		self.processfn = processfn
		if auxdataclass:
			self.auxdata = auxdataclass()
		else:
			self.auxdata = None
		self.reset()

		return

	# This method should be called when we want to use the same
	# multiapp_plot object for analyzing different apps, i.e. in the
	# first phase of generate_plots where we run analyze_trace.py
	# on each application (in the second stage of generate_plots,
	# we *want* to preserve the multiapp_plot across applications,
	# to generate a multi-app plot!).
	# This method clears the seriesdict, sets the workingdir and
	# currentapp, back to None, and sets pdffiles to []; it does
	# not change the plotname,
	# plotfn, nor datafn. Also, it DOES NOT touch self.auxdata - the
	# plot's resetfn should do this if it wants to reset this data.
	#
	# It's important to not change the .plotname because this is
	# used as a "key" for detecting duplicate plots in
	# remove_duplicates_from_plotlist().
	def reset(self):
		tag = "{}.reset".format(self.tag)

		self.workingdir = None
		self.currentapp = None
		if self.seriesdict:
			self.seriesdict.clear()
		else:
			self.seriesdict = dict()
		self.pdffiles = []
		self.resetfn(self.auxdata)

		return

	def __str__(self):
		s = ("{}[plotname={}, workingdir={}, currentapp={}, "
			"pdffiles={}]").format(self.tag, self.plotname,
			self.workingdir, self.currentapp, self.pdffiles)
		return s

	def add_pdffile(self, pdffile):
		self.pdffiles.append(pdffile)
		return

	# Sets the working directory for the multiapp_plot object:
	# workingdir = basedir + plotname (already set by constructor).
	# If the workingdir does not exist yet, it will also be created
	# now.
	def set_workingdir(self, basedir):
		tag = "{}.set_workingdir".format(self.tag)

		#if self.workingdir:
		#	# Expect this method to be called only once, unless a
		#	# reset() has been called in-between.
		#	# Nevermind, not anymore.
		#	print_unexpected(True, tag, ("workingdir is already set for "
		#		"this multiapp_plot: {}").format(self.workingdir))
		self.workingdir = "{}/{}".format(basedir, self.plotname)
		print_debug(tag, ("set workingdir to {}").format(self.workingdir))

		try:
			os.makedirs(self.workingdir)
			print_debug(tag, ("created workingdir {}").format(
				self.workingdir))
		except OSError:
			print_debug(tag, ("workingdir {} already exists").format(
				self.workingdir))

		return

	def set_currentapp(self, appname):
		tag = "{}.set_currentapp".format(self.tag)

		if self.currentapp:
			# Expect this method to be called only once, unless a
			# reset() has been called in-between.
			print_unexpected(True, tag, ("currentapp is already set for "
				"this multiapp_plot: {}").format(self.currentapp))
		self.currentapp = appname

		return

	# Currently intended for internal/private object use only!
	# Returns: a reference to the new series, which has been added to
	# the seriesdict, or None on error.
	def add_series(self, seriesname, appname, appserieslist):
		tag = "{}.add_series".format(self.tag)

		if not seriesname or not appname or appserieslist is None:
			print_error_exit(tag, ("invalid arg: seriesname={}, "
				"appname={}, appserieslist={}").format(
				seriesname, appname, appserieslist))

		newseries = series(seriesname, appname)
		appserieslist.append(newseries)
		print_debug(tag, ("serieslist for app {} now contains {} "
			"series").format(appname, len(appserieslist)))

		return newseries

	# Writes out a data file into the workingdir for every series
	# in the seriesdict.
	def serialize(self):
		tag = "{}.serialize".format(self.tag)

		if not self.workingdir:
			print_unexpected(True, tag, ("workingdir not set yet!"))
			return

		if not os.path.exists(self.workingdir):
			print_error_exit(tag, ("workingdir {} doesn't exist yet, "
				"expect it to be created already").format(
				self.workingdir))

		for appserieslist in self.seriesdict.values():
			print_debug(tag, ("serializing {} series into workingdir "
				"{}/").format(len(appserieslist), self.workingdir))
			for S in appserieslist:
				# IMPORTANT: filename format here must match the regex used
				# in deserialize()
				# This is kind of dumb: encoding data from series objects in
				# the filename...
				appname = S.appname
				if appname is None:
					print_unexpected(True, tag, ("got None appname"))
					#appname = NOAPPNAME
				fname = ("{}/{}~{}~{}.{}").format(self.workingdir,
					SERIESPREFIX, appname, S.seriesname, SERIESSUFFIX)
				S.serialize(fname)

		return

	# Attempts to read in series data files from the specified directory.
	def deserialize(self, searchdir):
		tag = "{}.deserialize".format(self.tag)

		# Find files containing '.dat':
		searchfor = ".{}".format(SERIESSUFFIX)
		seriesfiles = find_files_dirs(searchdir, searchfor,
				exactmatch=False, findfiles=True, finddirs=False,
				followlinks=True, absdirs=True)
		if len(seriesfiles) == 0:
			# A particular app may have ended up with no events for
			# some series, or the find_files_dirs command called up in
			# generate_plots.py may have found a directory with the
			# right name but without any data files. These are all ok.
			print_debug(tag, ("no seriesfiles found in "
				"searchdir {} with searchfor {}; returning now").format(
				searchdir, searchfor))
			return
		print_debug(tag, ("got back seriesfiles: {}").format(seriesfiles))

		for fname in seriesfiles:
			newseries = series('dummyseriesname', 'dummyappname')
			success = newseries.deserialize(fname)
			if not success:
				print_unexpected(True, tag, ("deserialize failed "
					"for new series, fname={}").format(fname))
			appserieslist = self.get_create_appserieslist(
					newseries.appname)
			appserieslist.append(newseries)
			print_debug(tag, ("serieslist for app {} now contains "
				"{} series").format(newseries.appname,
				len(appserieslist)))

		print_debug(tag, ("seriesdict now has series in it for "
			"{} apps after deserialization").format(len(self.seriesdict)))

		return

	# Looks for a serieslist in our seriesdict that matches the given
	# appname and returns it if it already exists, or creates an
	# empry serieslist, inserts it into the seriesdict, and returns it.
	def get_create_appserieslist(self, appname):
		tag = "{}.get_create_appserieslist".format(self.tag)

		# Key into seriesdict is now the appname (used to be seriesname):
		try:
			appserieslist = self.seriesdict[appname]
		except KeyError:
			appserieslist = list()
			self.seriesdict[appname] = appserieslist

		return appserieslist

	# Calls the plot's datafn and handles any new datapoints that it
	# returns.
	def consume_perf_sample(self, sample, leaderpid):
		tag = "{}.consume_perf_sample".format(self.tag)

		# It turns out that we can use consume_plot_event() to consume perf
		# samples as well - consume_plot_event() doesn't do anything with
		# the vma internals, so it's just up to the datafn to know that
		# it's working with a perf_sample rather than a vma.
		plot_event = PlotEvent(perf_sample=sample)
		return self.consume_plot_event(plot_event, leaderpid,
				sample.appname)

	# Returns: True if the datapoint was successfully processed by
	# the datafn and added to the series, False if there was an error.
	def consume_plot_event(self, plot_event, tgid, appname):
		tag = "{}.consume_plot_event".format(self.tag)

		#print_debug(tag, ("consuming a plot_event / event and attributing "
		#	"it to tgid {}").format(tgid))

		# (For plot_events with plot_event.vma set: )
		# What is this vma exactly? It comes from map_unmap_vma(), after
		# one of the following events in the trace:
		#   mmap_vma_alloc
		#   mmap_vma_free
		#   mmap_vma_resize_unmap / mmap_vma_resize_remap
		#   mmap_vma_reloc_unmap / mmap_vma_reloc_remap
		#   mmap_vma_access_unmap / mmap_vma_access_remap
		#   mmap_vma_flags_unmap / mmap_vma_flags_remap
		# The _alloc and *_remap events are considered "map" actions and
		# the _free and *_unmap events are considered "unmap" actions for
		# the purposes of the map_unmap_vma() method. For unmap actions,
		# the vma was just removed from the proc_info's vmatable and
		# marked as unmapped (vma.is_unmapped = True, vma.unmap_op set,
		# and vma.unmap_timestamp set). For map actions, vma is a new
		# vm_mapping object that was created and inserted into the
		# proc_info's vmatable (and all_vmas), with vma.vma_op set.
		#
		# So, the idea of a "vma" is somewhat conflated with an action /
		# operation on a vma. How can / should the plot datafns
		# distinguish between an explicit mmap_vma_alloc or _free and
		# an unmap / remap pair?? map_unmap_vma gets an argument "vma_op"
		# that should be set to one of these VMA_OP_TYPES:
		#   'alloc'
		#   'resize'
		#   'relocation'
		#   'access_change'
		#   'flag_change'
		# This field *is* passed to the vm_mapping constructor, and is
		# kept in vma.vma_op. Every alloc, resize, relocation,
		# access_change, or flag_change operation will result in the
		# creation of EXACTLY ONE vma with that vma_op. What about
		# frees? As part of an unmap-remap pair for the resize,
		# relocation, access_change, and flag_change operations, vmas
		# will be marked as "unmapped" (vma.is_unmapped == True), and
		# their .unmap_op will be set to the operation that is unmapping
		# this vma right now (.vma_op may not == .unmap_op).
		#
		# So, datafns that care about vma *counts* will only care about
		# vmas with .vma_op == 'alloc' or .unmap_op == 'free'. Datafns
		# that care about vma *sizes* will care about those vmas, and
		# ADDITIONALLY will care about vmas with .vma_op OR .unmap_op
		# == 'resize'! The other operations (relocation, access_change,
		# flag_change) are guaranteed to not change the size of the
		# vma during the unmap-remap.
		#
		# If the datafn only cares about, say, access_change operations,
		# it can consider only vmas with vma.vma_op == 'access_change'
		# AND is_unmapped == False (vmas passed in with is_unmapped
		# == True are the unmap part of an unmap-remap operation for
		# some .unmap_op operation).
		#   This all could be made somewhat cleaner if we made an explicit
		#   distinction between operations and vmas, rather than encoding
		#   it all into the vma / vm_mapping object, but oh well. In
		#   effect what the current encoding does is record every operation
		#   into two vmas, or something...
		# 
		# Is it ALWAYS the case that an unmap action is followed
		# immediately by a remap action? It should be - the event_pair
		# tracking and checking done in process_trace_file ensures this.
		#   In kernel functions where vmas are split and merged, any new
		#   vmas that are created or freed have explicit _alloc and _free
		#   trace events emitted! (in addition to unmap-remap pairs that
		#   may occur in these functions).
		#   E.g. here: one vma is unmapped + remapped, another vma is
		#   explicitly freed!
		#     mmap_vma_resize_unmap: pid=4426 tgid=4426 ptgid=4425
		#        [vma_merge cases 1,6 ... ffff8800c5553b80
		#     mmap_vma_resize_remap: pid=4426 tgid=4426 ptgid=4425
		#        [vma_merge cases 1,6 ... ffff8800c5553b80
		#     mmap_vma_free: pid=4426 tgid=4426 ptgid=4425
		#        [vma_merge cases 1,6 ... ffff8800cb101e60

		# The datafn returns a list of (seriesname, datapoint) tuples,
		# and expects this method to add each datapoint to its
		# corresponding series. The list may be empty.
		pointslist = self.datafn(self.auxdata, plot_event, tgid,
				appname)

		if pointslist is None or len(pointslist) == 0:
			#print_debug(tag, ("pointslist is None / empty, so not "
			#	"adding a datapoint and just returning success").format())
			return True

		appserieslist = self.get_create_appserieslist(appname)

		# Append each datapoint to a series in the app's serieslist:
		for (seriesname, datapoint) in pointslist:
			if datapoint is None:
				print_unexpected(True, tag, ("datapoint is None! "
					"seriesname={}").format(seriesname))

			# Look for a series in the appserieslist that matches the
			# seriesname that was returned. Using a list instead of
			# a map/tree is probably a bad idea for performance, but
			# the number of series per app is generally small...
			seriesmatch = None
			for series in appserieslist:
				if seriesname == series.seriesname:
					seriesmatch = series
					break

			if not seriesmatch:
				print_debug(tag, ("no series exists yet with name {}, "
					"creating it now").format(seriesname))
				seriesmatch = self.add_series(seriesname,
						appname, appserieslist)

			success = seriesmatch.append_datapoint(datapoint)
			if not success:
				print_error(tag, ("append_datapoint failed; "
					"seriesname={}, appname={}").format(seriesname,
					appname))
				return False
			#print_debug(tag, ("series {} for app {} now contains {} "
			#	"datapoints").format(seriesname, appname,
			#	len(seriesmatch.data)))

		return True

	def process_active_vmas(self, active_vmas, appname, app_pid):
		tag = "{}.process_active_vmas".format(self.tag)

		if not self.processfn:
			print_warning(tag, ("self.processfn not set, not "
				"processing active_vmas!"))
			return
		if active_vmas == None or len(active_vmas) == 0:
			print_warning(tag, ("active_vmas is {}, nothing to "
				"process").format(active_vmas))
			return

		plotevents = self.processfn(self.auxdata, active_vmas,
				appname, app_pid)
		if plotevents == None or len(plotevents) == 0:
			print_warning(tag, ("processfn returned plotevents={}; "
				"is this expected?").format(plotevents))
			return

		print_debug(tag, ("processing {} active_vmas created a "
			"list of {} plot events; passing them to consume_"
			"plot_event()").format(len(active_vmas), len(plotevents)))
		for plotevent in plotevents:
			self.consume_plot_event(plotevent, app_pid, appname)

		return

	# Performs the following steps:
	#   Calls plotfn to generate the multi-app plot
	#   Writes the generated plot to a .pdf file
	#   Appends the plot to the pdffiles, if previously specified
	#   Closes the plot/figure.
	# IMPORTANT: after complete() has been called, the plotfn may
	# have changed the seriesdict (i.e. it may have removed any
	# checkpoint series from it), so complete() should not be
	# called again!
	def complete(self):
		tag = "{}.complete".format(self.tag)

		if len(self.seriesdict) == 0:
			print_warning(tag, ("skipping plot {} because no "
				"series were added for it!").format(self.plotname))
			return

		# Note: it doesn't really make sense to pass auxdata to the
		# plotfn, since the plotfn will generally be called across
		# all apps, after serialization + deserialization has happened,
		# so auxdata is going to be empty / invalid anyway.
		print_debug(tag, ("plot {}: calling plotfn to generate "
			"plotfig, then will save into workingdir {}").format(
			self.plotname, self.workingdir))

		# IMPORTANT: plotfn() may/will modify the seriesdict (i.e. by
		# removing checkpoint series from it)! Additionally, the points
		# within the series may be modified (i.e. scaled by some factor),
		# and so on.
		plotfig = self.plotfn(self.seriesdict, self.plotname,
				self.workingdir)
		if not plotfig:
			print_warning(tag, ("plotfn did not return a fig as "
				"expected!").format())
			return
		print_debug(tag, ("got back plotfig from plotfn: type {}").format(
			type(plotfig)))
		print_debug(tag, ("plotfig has number {}").format(plotfig.number))

		plot_fname_no_ext = "{}/{}".format(self.workingdir, self.plotname)
		plots.save_close_plot(plotfig, plot_fname_no_ext, self.pdffiles)

		# Reset the plot object to ensure that nobody tries to plot
		# it again.
		self.reset()

		return

# Writes out the data for every plot in the plotlist - should be called
# at the end of an analysis for a single application.
# Returns: nothing
def serialize_plotlist_data(plotlist):
	tag = 'serialize_plotlist_data'

	for p in plotlist:
		print_debug(tag, ("serializing plot object {}").format(p.plotname))
		p.serialize()

	return

# Removes duplicate multiapp_plots from the plotlist, based on their
# .plotname. We're going to use the resulting list of plots to reconstruct
# the data from serialized files on disk, so it doesn't matter which
# plot we keep if there is more than one of a given name/type.
# Returns: a new list - the original list is unmodified.
def remove_duplicates_from_plotlist(plotlist):
	tag = 'remove_duplicates_from_plotlist'

	# NOTE: if you ever change this method, make sure that the members
	# of the plot object that are accessed are those that are not
	# reset by a call to p.reset()! The plots in the plotlist may
	# have already been completed once (during the analyze_trace.py
	# phase), and are now being re-used for the multi-app plot phase
	# (generate_plots.py).

	newlist = list()
	nameset = set()
	for p in plotlist:
		if p.plotname not in nameset:
			nameset.add(p.plotname)
			newlist.append(p)

	print_debug(tag, "plotlist:\n{} [{}]".format(
		'\n'.join(sorted(map(lambda p: p.plotname, plotlist))),
		len(plotlist)))
	print_debug(tag, " newlist:\n{} [{}]".format(
		'\n'.join(sorted(map(lambda p: p.plotname, newlist))),
		len(newlist)))

	return newlist

if __name__ == '__main__':
	print_error_exit("not an executable module")
