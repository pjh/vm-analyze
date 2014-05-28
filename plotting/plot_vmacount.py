# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.plots_common import *
import trace.vm_common as vm

##############################################################################
# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Constants are ok.
ONECATEGORYLIST = ['justonecategoryalwaysthesame']

class CategoriesDatapoint:
	def __init__(self, category, total):
		self.category = category
		self.total = total

class categories_auxdata:
	def __init__(self):
		return

def categories_resetfn(auxdata):
	return

class vmacount_auxdata:
	current_vmacount = None
	def __init__(self):
		self.current_vmacount = 0

def vmacount_resetfn(auxdata):
	auxdata.current_vmacount = 0
	return

class empty_auxdata:
	def __init__(self):
		return

def nop_resetfn(auxdata):
	return

##############################################################################

def categories_process_active_vmas(auxdata, active_vmas, appname, app_pid):
	tag = 'categories_process_active_vmas'

	return inner_process_active_vmas(auxdata, active_vmas, appname,
			app_pid, vm.classify_vma)

def max_vmas_process_active_vmas(auxdata, active_vmas,
		appname, app_pid):
	tag = 'max_vmas_process_active_vmas'

	# We want to re-use the code for categories, but really just
	# always return the same category.

	return inner_process_active_vmas(auxdata, active_vmas, appname,
			app_pid, lambda x: ONECATEGORYLIST)

# Takes a list of active_vmas from some point in time during the trace
# (e.g. when the maximum VM size was mapped), and creates plot
# events from these vmas. The 'classifier' method must take a vma
# as an arg and return a list of categories with length exactly 1.
# Returns: a list of PlotEvents, or None on error.
def inner_process_active_vmas(auxdata, active_vmas, appname, app_pid,
		classifier):
	tag = 'categories_process_active_vmas'

	# Note: eventually, we may want to call vm.ignore_vma() here to
	# ignore certain vmas, but for now the point of this plot is
	# to actually plot the vmas of all categories.

	totals = {}
	for vma in active_vmas:
		categories = classifier(vma)
		if categories is None or len(categories) == 0:
			print_warning(tag, ("no categories returned for vma "
				"{}").format(vma))
			continue

		if len(categories) != 1:
			# For this plot, we want the categories for vmas to
			# be non-overlapping.
			print_unexpected(True, tag, ("categories has len != 1: "
				"{}").format(categories))

		for cat in categories:
			try:
				totals[cat] += 1
			except KeyError:
				totals[cat] = 1
	
	plotevents = []
	for (cat, total) in totals.items():
		datapoint = CategoriesDatapoint(cat, total)
		plot_event = PlotEvent(datapoint=datapoint)
		plotevents.append(plot_event)
		print_debug(tag, ("added plot event: category {} has {} "
			"vmas").format(cat, total))
		
	return plotevents

##############################################################################
# This method is very similar to vm_size_datafn - if you modify one,
# you may want to modify the other.
def vmacount_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'vmacount_datafn'
	print_allocs_frees = False

	vma = plot_event.vma
	if vma is None:
		return None

	# Skip this vma if it's for a shared lib, guard region, etc.
	if vm.ignore_vma(vma):
		debug_ignored(tag, ("ignoring vma {}").format(vma))
		return None

	# See extensive comments in consume_plot_event() about how each
	# operation is encoded, especially frees!
	# Note: similar logic is used here for both vmacount_datafn() and
	# update_vm_size() - if you change one, examine the other one too.
	if ((vma.vma_op == 'alloc' or vma.vma_op == 'access_change') and
		not vma.is_unmapped):
		# Very first allocation of this vma, OR a remap for an access_change:
		# on an access_change, a vma that we were previously ignoring (e.g.
		# due to read-only permissions) may now be not-ignored (e.g. if its
		# permissions were changed to writeable), so we need to count the
		# vma here now.
		#   Ugh, this is complicated and ugly... effectively we're hiding
		#   the unmap-remap pairs for resizes, relocations, and
		#   flag_changes now, but not for access_changes, which is kind
		#   of inconsistent :-/
		auxdata.current_vmacount += 1
		point = datapoint()
		point.timestamp = vma.timestamp
		point.count = auxdata.current_vmacount
		if print_allocs_frees:
			print(("{} ALLOC [{}]: {}").format(tgid,
				str(auxdata.current_vmacount).zfill(4),
				vma.to_str_maps_format()))
	elif (vma.is_unmapped and 
		  (vma.unmap_op == 'free' or vma.unmap_op == 'access_change')):
		# Explicit free of this vma (no matter the operation that
		# allocated it (most recently operated on it)), OR an
		# unmap operation for an access_change: we can't ignore
		# access_change operations because when the vma is remapped,
		# we might ignore it (see ignore_vma() above), so we need
		# to un-count it here first!
		#   This access_change case definitely happens regularly:
		#   shared lib file vmas are mapped in as rw-p first, then
		#   changed to r--p.
		auxdata.current_vmacount -= 1
		point = datapoint()
		point.timestamp = vma.unmap_timestamp
		point.count = auxdata.current_vmacount
		if auxdata.current_vmacount < 0:
			print_error_exit(tag, ("current_vmacount hit {}; unmap "
				"timestamp is {}, vma is {}").format(
				auxdata.current_vmacount, vma.unmap_timestamp,
				vma.to_str_maps_format()))
		if print_allocs_frees:
			print(("{} FREE  [{}]: {}").format(tgid,
				str(auxdata.current_vmacount).zfill(4),
				vma.to_str_maps_format()))
	else:
		#print_debug(tag, ("vma_op={}, is_unmapped={}, unmap_op={}: "
		#	"not an explicit alloc or free, "
		#	"so ignoring this vma").format(vma.vma_op,
		#	vma.is_unmapped, vma.unmap_op))
		return None

	seriesname = currentapp
	point.appname = currentapp
	debug_ignored(tag, ("counted vma: {}").format(vma))
	debug_count(tag, ("{}  [series {}]").format(point.count, seriesname))
	#debug_ignored(tag, "")
	#debug_ignored(tag, "")

	return [(seriesname, point)]

# This method expects the plot_event to have its datapoint member
# set to a CategoriesDatapoint object.
def categories_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'categories_datafn'

	if not plot_event.datapoint:
		print_error(tag, ("got a plot_event without vma set: "
			"{}").format(plot_event))
		return None

	dp = plot_event.datapoint
	seriesname = dp.category
	return [(seriesname, dp.total)]

##############################################################################

def vmacount_ts_plotfn(seriesdict, plotname, workingdir):
	tag = 'vmacount_ts_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict)

	# Set up y-axis splits: set to None to just use one plot, or pass
	# a list of maximum y-values and plot_time_series will split up
	# the series into multiple plots, each plot with a different y-axis.
	#ysplits = []
	#ysplits = [150]
	ysplits = [150, 1000]

	title = ("VMAs mapped over time").format()
	xaxis = "Execution time"
	yaxis = "Currently-mapped VMAs"
	return plot_time_series(plotdict, title, xaxis, yaxis, ysplits,
			logscale=False, cp_series=cp_series)

def vmacount_max_col_plotfn(seriesdict, plotname, workingdir):
	tag = 'vmacount_max_col_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict, usemax=True)
	  # Convert dictionary of series (lists of datapoints) to a dictionary
	  # of maximum vmacounts

	title = ("Maximum mapped VMAs (old way, without deduplication)").format()
	xlabel = ''
	ylabel = 'Mapped VMAs'
	return plot_columns_old(plotdict, title, xlabel, ylabel, sortcolumns=True,
			logscale=False)

def categories_plotfn(appseriesdict, plotname, workingdir):
	tag = 'categories_plotfn'

	categories = vm.VMA_CATEGORIES
	#title = ("VMAs by category").format()
	title = ("Maximum VMAs by category").format()
	ysplits = [1000]

	return inner_plotfn(appseriesdict, plotname, workingdir, categories,
			title, which='sidebyside', logscale=True, ysplits=ysplits)

def max_vmas_plotfn(appseriesdict, plotname, workingdir):
	tag = 'max_vmas_plotfn'
	
	categories = ONECATEGORYLIST
	title = ("Maximum mapped VMAs").format()
	ysplits = [1000]

	return inner_plotfn(appseriesdict, plotname, workingdir, categories,
			title, which='stacked', logscale=True, ysplits=ysplits)

def inner_plotfn(appseriesdict, plotname, workingdir, categories, title,
		which='stacked', logscale=False, ysplits=None):
	tag = 'inner_plotfn'

	cp_series = handle_cp_series(appseriesdict)
	if cp_series:
		print_unexpected(True, tag, ("cp_series shouldn't be "
			"valid here, right? {}").format(cp_series))

	# appseriesdict maps an app name to a list of series for that app.
	# Each app's series will be named with a category from
	# categories, and the lone datapoint for the series
	# will be the count of vmas with that category. We need to
	# construct a plotdict that matches the description in the
	# comments for plot_stacked_columns().
	plotdict = dict()
	for (appname, appserieslist) in appseriesdict.items():
		innerdict = dict()
		for S in appserieslist:
			# Construct inner dict: map vma categories (series
			# name) to counts.
			if len(S.data) != 1:
				print_unexpected(True, tag, ("app {}, series {}: "
					"len(S.data) is {}, expect 1! {}").format(
					appname, S.seriesname, len(S.data), S.data))
			if type(S.data[0]) != int:
				print_unexpected(True, tag, ("app {}, series {}: "
					"type(S.data[0]) is {}, expect int!").format(
					appname, S.seriesname, type(S.data[0])))
			category = S.seriesname
			if category not in categories:
				print_unexpected(True, tag, ("app {}, series {}: "
					"name not in VMA_CATEGORIES {}").format(
					appname, S.seriesname, categories))
			innerdict[category] = S.data[0]
		plotdict[appname] = innerdict
		print_debug(tag, ("plotdict[{}] -> {}").format(appname,
			plotdict[appname]))

	xlabel = ''
	ylabel = 'Mapped VMAs'
	if which == 'sidebyside':
		return plot_sidebyside_columns(categories, plotdict,
				title, xlabel, ylabel, sortcolumns='ascending',
				logscale=True)   # no ysplits
	else:
		return plot_stacked_columns(categories, plotdict,
				title, xlabel, ylabel, sortcolumns='ascending',
				logscale=True, ysplits=ysplits)

##############################################################################

vmacount_ts_plot = multiapp_plot('vma-counts', vmacount_auxdata,
		vmacount_ts_plotfn, vmacount_datafn, vmacount_resetfn)
vmacount_max_col_plot = multiapp_plot('max-regions-old', vmacount_auxdata,
		vmacount_max_col_plotfn, vmacount_datafn, vmacount_resetfn)

# suffix should describe the point-in-time when this plot's data is
# being calculated.
def new_categories_cols_plot(suffix, outputdir):
	plotname = "categories_cols-{}".format(suffix)
	newplot = multiapp_plot(plotname, categories_auxdata,
			categories_plotfn, categories_datafn,
			categories_resetfn, processfn=categories_process_active_vmas)
	newplot.set_workingdir(outputdir)
	return newplot

# suffix should describe the point-in-time when this plot's data is
# being calculated.
def new_max_vmas_cols_plot(suffix, outputdir):
	plotname = "max_vmas_cols-{}".format(suffix)
	newplot = multiapp_plot(plotname, categories_auxdata,
			#max_vmas_plotfn, max_vmas_datafn,
			max_vmas_plotfn, categories_datafn,
			categories_resetfn, processfn=max_vmas_process_active_vmas)
	newplot.set_workingdir(outputdir)
	return newplot

if __name__ == '__main__':
	print_error_exit("not an executable module")
