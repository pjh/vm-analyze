# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.PlotEvent import PlotEvent
from plotting.plots_common import *
import trace.vm_common as vm

##############################################################################
# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Only use "constants".

class empty_auxdata:
	def __init__(self):
		return

def nop_resetfn(auxdata):
	return

class VMA_Sizes_Datapoint:
	def __init__(self, size, count):
		self.size = size
		self.count = count
		return

##############################################################################

# Takes a list of active_vmas from some point in time during the trace
# (e.g. when the maximum VM size was mapped), and creates plot
# events from these vmas.
# Returns: a list of PlotEvents, or None on error.
def vma_size_process_active_vmas(auxdata, active_vmas, appname, app_pid):
	tag = 'vma_size_process_active_vmas'

	# For this plot, we want to create a column plot of vma
	# counts by size. However, since vma sizes can be any multiple
	# of the base page size, we want to bin the sizes into powers-of-2;
	# do this here by *rounding each vma's length up* to the nearest
	# power of 2, then building a dict that tracks the counts of
	# vmas belonging to each bin.
	vmas_by_size = {}
	for vma in active_vmas:
		rounded_size = vm.nextpowerof2(vma.length)
		try:
			vmas_by_size[rounded_size] += 1
		except KeyError:
			vmas_by_size[rounded_size] = 1
	
	plot_events = []
	for (size, count) in vmas_by_size.items():
		datapoint = VMA_Sizes_Datapoint(size, count)
		plot_event = PlotEvent(datapoint=datapoint)
		plot_events.append(plot_event)

	return plot_events

##############################################################################

# This method expects the plot_event to have its datapoint member set
# to a VMA_Sizes_Datapoint.
def vma_size_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'vma_size_datafn'

	if not plot_event.datapoint:
		print_error(tag, ("got a plot_event without a datapoint "
			"set").format())
		return None

	# series datapoints are simply the size, which is used for the
	# series name, and the count of vmas with that size.
	dp = plot_event.datapoint
	seriesname = dp.size
	count = dp.count
	return [(seriesname, count)]

##############################################################################

# Takes the list of series for a given app and puts its size-count
# pairs into a dict that is returned. The keys for the dict are
# string *labels*, not ints (i.e. they are all found in
# vm.VMA_SIZES_LABELS).
# If fill_empty_labels is True, then this method will fill in keys
# with 0 counts for any labels in vm.VMA_SIZES_LABELS that were not
# found in the application's series.
def vma_size_series_to_dict(appserieslist, fill_empty_labels=True):
	tag = 'vma_size_series_to_dict'

	total_vmas = 0
	total_vm_size = 0
	sizesdict = dict()
	for S in appserieslist:
		# Construct inner dict: map vma size labels (strings),
		# which come from seriesnames (ints), to counts.
		if len(S.data) != 1:
			print_unexpected(True, tag, ("app {}, series {}: "
				"len(S.data) is {}, expect 1! {}").format(
				appname, S.seriesname, len(S.data), S.data))
		if type(S.data[0]) != int:
			print_unexpected(True, tag, ("app {}, series {}: "
				"type(S.data[0]) is {}, expect int!").format(
				appname, S.seriesname, type(S.data[0])))

		# size should already be an int power-of-2 representing
		# the maximum vma length for this bin, from the
		# process_active_vmas method:
		size = S.seriesname
		if type(size) != int:
			print_unexpected(True, tag, ("expect type(size) "
				"= int, but it is {}").format(type(size)))
		count = S.data[0]
		if type(count) != int:
			print_unexpected(True, tag, ("expect type(count) "
				"= int, but it is {}").format(type(count)))
		
		try:
			label = vm.VMA_SIZES_MAP[size]
			sizesdict[label] = count
		except KeyError:
			# We could end up with multiple datapoints for sizes
			# beyond VMA_SIZES_MAX, so need another try-except
			# here to update existing count.
			if size > vm.VMA_SIZES_MAX:
				label = vm.VMA_SIZES_GREATER_LABEL
				try:
					sizesdict[label] += count
				except KeyError:
					sizesdict[label] = count
			else:
				print_unexpected(True, tag, ("got non-power-of-2 "
					"size {}? VMA_SIZES_MAP={}").format(size,
					vm.VMA_SIZES_MAP))
		total_vmas += count
		total_vm_size += (size * count)

	if fill_empty_labels:
		for key in vm.VMA_SIZES_LABELS:
			try:
				exists = sizesdict[key]
			except KeyError:
				sizesdict[key] = 0
		if len(sizesdict) != len(vm.VMA_SIZES_LABELS):
			print_unexpected(True, tag, ("len(sizesdict) {} != "
				"len(VMA_SIZES_LABELS) - how did this happen??").format(
				len(sizesdict), len(vm.VMA_SIZES_LABELS)))

	return (sizesdict, total_vmas, total_vm_size)

def vma_size_cols_plotfn(appseriesdict, plotname, workingdir):
	tag = 'vma_size_cols_plotfn'

	# seriesdict maps an app name to a list of series for that app.
	# Each series is named with the (integer) size value, and each
	# series should have a single datapoint with count of vmas that
	# had that size.
	# For this data, we want to produce a column plot; what should
	# it look like with multiple applications? Should the "major"
	# ticks on the x-axis be the applications, with each application's
	# size columns all next to each other? Or the reverse: the major
	# ticks are the sizes, with all of the columns for that size
	# from every application next to each other? I think the latter,
	# for now... (I'm not sure this plot will be very pretty / useful
	# with multiple apps on it...).
	# Construct a plotdict that matches the description in the comments
	# for plot_sidebyside_columns().
	plotdict = dict()
	for (appname, appserieslist) in appseriesdict.items():
		(sizesdict, total_vmas, total_vm_size) = vma_size_series_to_dict(
				appserieslist, fill_empty_labels=False)
		plotdict[appname] = sizesdict
		#print_debug(tag, ("plotdict[{}] -> {}").format(appname,
		#	plotdict[appname]))

	if len(plotdict) == 1:
		title = ("{}: VMAs by size").format(appname)
	else:
		title = ("VMAs by size").format()
	xlabel = ''
	ylabel = 'VMA count'
	return plot_sidebyside_columns(vm.VMA_SIZES_LABELS, plotdict,
			title, xlabel, ylabel, sortcolumns='ascending',
			logscale=False, labels_on_xaxis=True, needs_legend=False)

def vma_size_cdf_plotfn(appseriesdict, plotname, workingdir):
	tag = 'vma_size_cdf_plotfn'

	# seriesdict maps an app name to a list of series for that app.
	# Each series is named with the (integer) size value, and each
	# series should have a single datapoint with count of vmas that
	# had that size.
	# For this data, we want to produce a CDF of the counts of vmas
	# with each size.
	plotdict = dict()
	for (appname, appserieslist) in appseriesdict.items():
		# Get the sizesdict, which maps size labels to counts.
		# Then, count up the total number of vmas for this app,
		# calculate the cumulative % of all vmas for each size,
		# and create a list of points for the line plot. The
		# list must have exactly one point for every entry in
		# vm.VMA_SIZES_LABELS.
		(sizesdict, total_vmas, total_vm_size) = vma_size_series_to_dict(
				appserieslist)
		if total_vmas == 0:
			print_error(tag, ("got total_vmas={}, returning now "
				"before we divide by 0").format(total_vmas))
			return None

		# VMA_SIZES_LABELS should be in ascending order, so we add
		# up the CDF values from smallest vma size/bin to largest.
		# Points must be a "datapoint" or "SmallDatpoint" from
		# plots_common.
		cumulative = 0
		pointlist = []
		for label in vm.VMA_SIZES_LABELS:
			try:
				count = sizesdict[label]
				cumulative += count
				cum_percent = cumulative / total_vmas
				pointlist.append(SmallDatapoint(cum_percent))
			except KeyError:
				print_error_exit(tag, ("label {} not found in "
					"sizesdict, but fill_empty_labels was True, "
					"so this is never expected!").format(label))
		if cumulative != total_vmas:
			print_error_exit(tag, ("cumulative={}, total_vmas={}").format(
				cumulative, total_vmas))
		plotdict[appname] = pointlist
		print_debug(tag, ("{}: CDF points are {}").format(appname,
			list(zip(vm.VMA_SIZES_LABELS,
				map(lambda p: p.count, pointlist)))))

	if len(plotdict) == 1:
		title = ("{}: CDF of VMA sizes").format(appname)
	else:
		title = ("CDF of VMA sizes").format()
	xlabel = ''
	ylabel = 'Percentage of all VMAs'
	return plot_lineplot(plotdict, title, xlabel, ylabel,
			vm.VMA_SIZES_LABELS, None, yax_units='percents',
			#show_markers=False,
			vertical_xlabels=True)

def vma_size_portion_plotfn(appseriesdict, plotname, workingdir):
	tag = 'vma_size_portion_plotfn'

	# seriesdict maps an app name to a list of series for that app.
	# Each series is named with the (integer) size value, and each
	# series should have a single datapoint with count of vmas that
	# had that size.
	plotdict = dict()
	for (appname, appserieslist) in appseriesdict.items():
		# Get the sizesdict, which maps size labels to counts.
		(sizesdict, total_vmas, total_vm_size) = vma_size_series_to_dict(
				appserieslist)
		if total_vm_size == 0:
			print_error(tag, ("got total_vm_size={}, returning "
				"before we divide by 0").format(total_vm_size))
			return None

		# Points must be a "datapoint" or "SmallDatapoint" from
		# plots_common.
		cumulative_vm_size = 0
		pointlist = []
		for i in range(len(vm.VMA_SIZES_LABELS)):
			if i < len(vm.VMA_SIZES_LABELS) - 1:
				vma_size = vm.VMA_SIZES[i]
				label    = vm.VMA_SIZES_LABELS[i]
				try:
					count = sizesdict[label]
				except KeyError:
					print_error_exit(tag, ("label {} not found in "
						"sizesdict, but fill_empty_labels was True, "
						"so this is never expected!").format(label))
				cumulative_vm_size += vma_size * count
			else:
				# Last point: vmas with sizes greater than
				# vm.VMA_SIZES[-1]. vma_size_series_to_dict() has lost
				# the information about the absolute sizes of these
				# vmas, but for this plot, it does not matter - we're
				# adding the final point here, which will always be
				# 1.0 (100%).
				cumulative_vm_size = total_vm_size
			cum_percent = cumulative_vm_size / total_vm_size
			pointlist.append(SmallDatapoint(cum_percent))

		plotdict[appname] = pointlist
		print_debug(tag, ("{}: portion points are {}").format(appname,
			list(zip(vm.VMA_SIZES_LABELS,
				map(lambda p: p.count, pointlist)))))

	title = ("Cumulative virtual memory mapped by VMA size").format()
	if len(plotdict) == 1:
		title = ("{}: {}").format(appname, title)
	xlabel = ''
	ylabel = 'Percentage of mapped virtual memory'
	return plot_lineplot(plotdict, title, xlabel, ylabel,
			vm.VMA_SIZES_LABELS, None, yax_units='percents',
			#show_markers=False,
			vertical_xlabels=True)

##############################################################################

# suffix should describe the point-in-time when this plot's data is
# being calculated.
def new_vma_size_cols_plot(suffix, outputdir):
	plotname = "vma-size-columns-{}".format(suffix)
	new_sizes_plot = multiapp_plot(plotname, empty_auxdata,
			vma_size_cols_plotfn, vma_size_datafn, nop_resetfn,
			processfn=vma_size_process_active_vmas)
	new_sizes_plot.set_workingdir(outputdir)
	return new_sizes_plot

def new_vma_size_cdf_plot(suffix, outputdir):
	plotname = "vma-size-cdf-{}".format(suffix)
	newplot = multiapp_plot(plotname, empty_auxdata,
			vma_size_cdf_plotfn, vma_size_datafn, nop_resetfn,
			processfn=vma_size_process_active_vmas)
	newplot.set_workingdir(outputdir)
	return newplot

def new_vma_size_portion_plot(suffix, outputdir):
	plotname = "vma-size-portion-{}".format(suffix)
	newplot = multiapp_plot(plotname, empty_auxdata,
			vma_size_portion_plotfn, vma_size_datafn, nop_resetfn,
			processfn=vma_size_process_active_vmas)
	newplot.set_workingdir(outputdir)
	return newplot

if __name__ == '__main__':
	print_error_exit("not an executable module")
