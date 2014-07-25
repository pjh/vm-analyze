# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.PlotEvent import PlotEvent
from plotting.plots_common import *
import trace.vm_common as vm

CANDIDATE_BASEPAGESIZES = {
		  '4KB'		:   4 * KB_BYTES,
		  '8KB'		:   8 * KB_BYTES,
		 '16KB'		:  16 * KB_BYTES,
		 '32KB'		:  32 * KB_BYTES,
		 '64KB'		:  64 * KB_BYTES,
		'128KB'		: 128 * KB_BYTES,
		'256KB'		: 256 * KB_BYTES,
		'512KB'		: 512 * KB_BYTES,
		  '1MB'		:   1 * MB_BYTES,
		  '2MB'		:   2 * MB_BYTES,
		  '4MB'		:   4 * MB_BYTES,
		# '16MB'		:  16 * MB_BYTES,
		# '64MB'		:  64 * MB_BYTES,
		#'256MB'		: 256 * MB_BYTES,
	}

##############################################################################
# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Only use "constants".

class empty_auxdata:
	def __init__(self):
		return

def nop_resetfn(auxdata):
	return

class OSDatapoint:
	# "txln" == translation
	def __init__(self, seriesname, num_txln_entries):
		self.seriesname = seriesname
		self.num_txln_entries = num_txln_entries

class BPSDatapoint:   # "BPS" == "base page size"
	# count is either the number of pages needed to map all of the
	# vmas, or the total bytes of fragmentation introduced by this
	# base page size. seriesname must be set appropriately to match
	# count.
	def __init__(self, seriesname, bps_label, count):
		self.seriesname = seriesname
		self.bps_label = bps_label
		self.count = count

##############################################################################

# Takes a list of active_vmas from some point in time during the trace
# (e.g. when the maximum VM size was mapped), and creates plot
# events from these vmas.
# Returns: a list of PlotEvents, or None on error.
def os_process_active_vmas(auxdata, active_vmas, appname, app_pid):
	tag = 'os_process_active_vmas'

	# Ok, we want to calculate the number of "translation entries"
	# that would be needed to map all of the vmas in the active_vmas
	# list to physical pages / segments, for particular combinations
	# of page / segment sizes. For example, if we directly mapped
	# each vma with a segment of exactly the right size, then we
	# would need just one translation entry per vma - this is one
	# datapoint to pass to the plot. With just 4 KB pages, we'll need
	# a whole lot more translation entries - this is another datapoint.
	plotevents = []
	txln_entries = len(active_vmas)
	seriesname = 'segments'
	datapoint = OSDatapoint(seriesname, txln_entries)
	plot_event = PlotEvent(datapoint=datapoint)
	plotevents.append(plot_event)

	# For each set of translation entry sizes that we want to consider,
	# create a mapping in this dict, from the name/description to a
	# list of sizes (in bytes).
	# IMPORTANT: the lists here must be sorted from smallest size to
	# largest.
	txln_size_dict = {
			'4KB'			: [vm.PAGE_SIZE_4KB],
			'4KB,2MB'		: [vm.PAGE_SIZE_4KB, vm.PAGE_SIZE_2MB],
			'4KB,2MB,1GB'	: [vm.PAGE_SIZE_4KB, vm.PAGE_SIZE_2MB,
							   vm.PAGE_SIZE_1GB],
		}
	for (descr, txln_sizes) in txln_size_dict.items():
		total_entries_needed = 0
		for vma in active_vmas:
			# Ignore shared lib vmas, etc.:
			if vm.ignore_vma(vma):
				debug_ignored(tag, ("ignoring vma: {}").format(vma))
			else:
				entries_needed = vm.txln_entries_needed(txln_sizes, vma)
				total_entries_needed += sum(entries_needed)
				  # ignore different entry sizes for now

		print_debug(tag, ("adding OSDatapoint: {}, {}").format(
			descr, total_entries_needed))
		datapoint = OSDatapoint(descr, total_entries_needed)
		plot_event = PlotEvent(datapoint=datapoint)
		plotevents.append(plot_event)

	return plotevents

# Takes a list of active_vmas from some point in time during the trace
# (e.g. when the maximum VM size was mapped), and creates plot
# events from these vmas.
# Returns: a list of PlotEvents, or None on error.
def bps_process_active_vmas(auxdata, active_vmas, appname, app_pid):
	tag = 'bps_process_active_vmas'

	# In this processing method, we want to calculate the amount
	# of additional fragmentation that would occur if we mapped
	# the vmas in the active_vmas list with base pages of varying
	# sizes.
	#
	# Notes:
	#   This fragmentation is the fragmentation *beyond* the fragmentation
	#   that already exists with 4 KB base pages; some fragmentation will
	#   already exist with 4 KB base pages because the minimum vma size
	#   is forced up to this size, but we can't know that fragmentation
	#   here.
	
	plotevents = []

	# items() gets key-value pairs in hash-table order, so sort by
	# increase bps - this will result in datapoints being added to
	# series by increasing bps, so that when the series are used later
	# we don't have to sort again.
	sortedbps = sorted(CANDIDATE_BASEPAGESIZES.items(),
	                     key=lambda pair: pair[1])
	for (bps_label, bps) in sortedbps:
		# For each candidate bps, we add two datapoints to two separate
		# series: one for the total number of pages needed to map all
		# of the vmas, and one for the total bytes of fragmentation that
		# would result from this mapping.
		total_pages = 0
		total_frag = 0
		total_vmsize = 0
		for vma in active_vmas:
			# Ignore shared lib vmas, etc.:
			if vm.ignore_vma(vma):
				debug_ignored(tag, ("ignoring vma: {}").format(vma))
			else:
				(pages, frag) = vm.pages_needed(bps, vma.length)
				total_pages += pages
				total_frag += frag
				total_vmsize += vma.length
		
		datapoint = BPSDatapoint('totalpages', bps_label,
				total_pages)
		plot_event = PlotEvent(datapoint=datapoint)
		plotevents.append(plot_event)
		
		datapoint = BPSDatapoint('fragmentation', bps_label,
				total_frag)
		plot_event = PlotEvent(datapoint=datapoint)
		plotevents.append(plot_event)

		# 'overhead': new overhead of internal fragmentation, expressed
		#   as a percentage of the original virtual memory size.
		datapoint = BPSDatapoint('overhead', bps_label,
				float(total_frag / total_vmsize))
		plot_event = PlotEvent(datapoint=datapoint)
		plotevents.append(plot_event)

	return plotevents

##############################################################################

# This method expects the plot_event to have its datapoint member set
# to an OSDatapoint object.
def os_datapoint_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'os_datapoint_datafn'

	if not plot_event.datapoint:
		print_error(tag, ("got a plot_event without a datapoint "
			"set").format())
		return None

	# The OSDatapoint already has pretty much the format that we need:
	# a seriesname, and a "count" which is the number of "translation
	# entries" (pages/segments needed to map the process' virtual
	# address space regions - the particular type/size pages/segments
	# are described by the seriesname).
	dp = plot_event.datapoint
	return [(dp.seriesname, dp.num_txln_entries)]

# This method expects the plot_event to have its datapoint member set
# to an BPSDatapoint object.
def bps_datapoint_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'bps_datapoint_datafn'

	if not plot_event.datapoint:
		print_error(tag, ("got a plot_event without a datapoint "
			"set").format())
		return None

	# Pull the seriesname out of the BPSDatapoint, and then just return
	# the whole thing (which includes the bps label and a "count" of
	# either the number of pages needed for mapping or the total bytes
	# of fragmentation introduced); the plotfn will pull out those
	# members and use them to build a plot.
	dp = plot_event.datapoint
	return [(dp.seriesname, dp)]

##############################################################################

def os_tablefn(seriesdict, plotname, workingdir):
	tag = 'os_tablefn'

	print_debug(tag, ("entered: plotname={}, seriesdict has {} "
		"appserieslists in it").format(plotname, len(seriesdict)))
	if len(seriesdict) == 0:
		print_warning(tag, ("seriesdict is empty, not producing "
			"the table").format())
		return
	
	fname = "{}/os-overheads-table".format(workingdir)
	f = open(fname, 'w')

	firstcolwidth = len('Application') + 1
	colwidth = 12

	# To construct the header, we need the names of the series
	# that were added for the apps. Unfortunately, there's no
	# guarantee that the same series were added for every app...
	# just assume this for now, and get the header fields / series
	# names from the first app.
	appserieslists = list(seriesdict.values())
	seriesnames = sorted(map(lambda S: S.seriesname, appserieslists[0]))
	header = ["Application".rjust(firstcolwidth)]
	for sname in seriesnames:
		header.append("{}".format(sname.rjust(colwidth)))

	f.write("Number of translation entries needed:\n")
	f.write("\n")
	f.write("{}\n".format('\t'.join(header)))

	# Sort rows by appname:
	pairs = sorted(list(seriesdict.items()), key=lambda pair: pair[0])
	for (appname, appserieslist) in pairs:
		# Sort columns by seriesname (in the same way that the seriesnames
		# headers are sorted above); for now, assume that everything
		# just matches up.
		series = sorted(appserieslist, key=lambda S: S.seriesname)
		line = ["{}".format(appname.rjust(firstcolwidth))]
		for S in series:
			# In each series, we only expect a single datapoint: the
			# number of translation entries needed to map all of the
			# app's vmas at the particular point-in-time when the
			# overheads analysis was performed.
			data = S.data
			if len(data) != 1:
				print_error(tag, ("series {} has {} datapoints, "
					"expect just 1!").format(S.seriesname, len(S.data)))
				continue
			#entries_needed = S.data[0].count
			entries_needed = S.data[0]
			  # not a datapoint(), just an int right now
			line.append("{}".format(str(entries_needed).rjust(colwidth)))
		f.write("{}\n".format('\t'.join(line)))

	f.close()

	return

# Important: this method should not modify the seriesdict - it will
# also be used to generate a plot after this method returns!
def bps_tablefn(seriesdict, plotname, workingdir):
	tag = 'bps_tablefn'

	if len(seriesdict) == 0:
		print_warning(tag, ("seriesdict is empty, not producing "
			"the table").format())
		return
	
	fname = "{}/basepagesizes-fragmentation".format(workingdir)
	fragfile = open(fname, 'w')
	fname = "{}/basepagesizes-overhead".format(workingdir)
	overheadfile = open(fname, 'w')

	firstcolwidth = len('Application') + 1
	colwidth = 12

	# For now, we assume that all series will have exactly the same
	# labels (which come from the CANDIDATE_BASEPAGESIZES dict used
	# in bps_process_active_vmas). These labels are used for the
	# column titles for all of the series/table types.
	firstseries = True
	col_labels = []

	for (appname, serieslist) in sorted(seriesdict.items(),
	                                    key=lambda pair: pair[0]):

		# From bps_process_active_vmas, we expect each app to have
		# two series: one for 'totalpages' and one for 'fragmentation'.
		# For now, ignore the totalpages series, and just build a
		# table with the fragmentation values:
		for S in serieslist:
			if S.seriesname == 'totalpages':
				pass
			elif (S.seriesname == 'fragmentation' or
			      S.seriesname == 'overhead'):
				fheader = ["Application".rjust(firstcolwidth)]
				fline = [appname.rjust(firstcolwidth)]
				for i in range(len(S.data)):
					point = S.data[i]
					if firstseries:
						col_labels.append(point.bps_label)
						fheader.append(point.bps_label.rjust(colwidth))
					else:
						if point.bps_label != col_labels[i]:
							print_error_exit(tag, ("i={}, col_labels="
								"{}; expect series to have same labels "
								"in same order, but got bps_label="
								"{}").format(i, col_labels,
								point.bps_label))
					if S.seriesname == 'fragmentation':
						fline.append("{}".format(
							pretty_bytes(point.count).rjust(colwidth)))
					elif S.seriesname == 'overhead':
						fline.append("{}".format(
							to_percent(point.count, 2).rjust(colwidth)))

				# Write the table header for the first series, then
				# always write a line for this app:
				if firstseries:
					fragfile.write("Bytes of internal fragmentation:\n")
					fragfile.write("\n")
					fragfile.write("{}\n".format('\t'.join(fheader)))
					overheadfile.write("Additional fragmentation overhead:\n")
					overheadfile.write("\n")
					overheadfile.write("{}\n".format('\t'.join(fheader)))
					firstseries = False
				if S.seriesname == 'fragmentation':
					fragfile.write("{}\n".format('\t'.join(fline)))
				elif S.seriesname == 'overhead':
					overheadfile.write("{}\n".format('\t'.join(fline)))
			else:
				print_error(tag, ("unexpected S.seriesname {}").format(
					S.seriesname))

	fragfile.close()
	overheadfile.close()

	return

def os_plotfn(seriesdict, plotname, workingdir):
	tag = 'os_plotfn'

	# seriesdict maps an app name to a list of series for that app.
	os_tablefn(seriesdict, plotname, workingdir)

	return None

def bps_plotfn(seriesdict, plotname, workingdir):
	tag = 'bps_plotfn'

	bps_tablefn(seriesdict, plotname, workingdir)
	
	# seriesdict maps an app name to a list of series for that app.
	# For this data, we want to produce a labeled line plot, which
	# is not quite the same as a timeseries plot. I thought about
	# moving this code into a separate method for generic labeled
	# (non-timeseries) plots, but because it relies on the specific
	# BPSDatapoint object right now, I didn't.
	xlabels = []
	plotdict = dict()
	firstapp_firstseries = True
	hackcount = 0   # hopefully not ever used...
	for appserieslist in seriesdict.values():
		for S in appserieslist:
			if S.seriesname != 'overhead':  # just plot %s for now
				continue
			
			# For now, since we're just plotting % overhead, use just
			# the appname for the plot seriesname; this may have to
			# change later...
			seriesname = "{}".format(S.appname)
			try:
				exists = plotdict[seriesname]
				# This may happen e.g. if you put multiple trace runs
				# from the same app into the same results directory
				# and try to generate plots for that directory...
				print_unexpected(True, tag, ("got multiple series "
					"with name {}").format(seriesname))
				hackcount += 1
				seriesname = "{}-{}".format(S.appname, hackcount)
			except KeyError:
				pass
			#print_debug(tag, "using seriesname={} (appname="
			#	"{})".format(seriesname, S.appname))

			plot_points = list()
			for i in range(len(S.data)):
				bps_point = S.data[i]
				#print_debug(tag, ("bps_point: label={}, "
				#	"count={}").format(bps_point.bps_label,
				#	bps_point.count))
				if firstapp_firstseries:
					xlabels.append(bps_point.bps_label)
				else:
					if bps_point.bps_label != xlabels[i]:
						print_error_exit(tag, ("i={}, xlabels="
							"{}; expect series to have same labels "
							"in same order, but got bps_label="
							"{}").format(i, xlabels,
							bps_point.bps_label))
				plot_point = datapoint()
				plot_point.count = bps_point.count
				plot_points.append(plot_point)
			
			plotdict[seriesname] = plot_points
			firstapp_firstseries = False

	title = ("Internal fragmentation overhead for base page sizes").format()
	xaxis = "Base page size"
	yaxis = "Percent overhead"
	ysplits = []
	hlines = [0.01]
	return plot_lineplot(plotdict, title, xaxis, yaxis, xlabels, ysplits,
			yax_units='percents', logscale=True, hlines=hlines,
			vertical_xlabels=True)

##############################################################################

# suffix should describe the point-in-time when this plot's data is
# being calculated.
def new_os_overheads_plot(suffix, outputdir):
	plotname = "os-overheads-{}".format(suffix)
	new_os_plot = multiapp_plot(plotname, empty_auxdata, os_plotfn,
			os_datapoint_datafn, nop_resetfn,
			processfn=os_process_active_vmas)
	new_os_plot.set_workingdir(outputdir)
	return new_os_plot

# suffix should describe the point-in-time when this plot's data is
# being calculated.
def new_basepagesize_plot(suffix, outputdir):
	plotname = "basepagesize-{}".format(suffix)
	new_bps_plot = multiapp_plot(plotname, empty_auxdata, bps_plotfn,
			bps_datapoint_datafn, nop_resetfn,
			processfn=bps_process_active_vmas)
	new_bps_plot.set_workingdir(outputdir)
	return new_bps_plot

if __name__ == '__main__':
	print_error_exit("not an executable module")
