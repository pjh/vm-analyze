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

class vmaops_auxdata:
	def __init__(self):
		self.opcounts = dict()
		self.veryfirstvma = True
		return

def vmaops_resetfn(auxdata):
	auxdata.opcounts.clear()
	auxdata.veryfirstvma = True
	return

def vmaops_all_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['alloc', 'free', 'resize', 'relocation', 'access_change',
			'flag_change']
	label_series_with_app = True
	combine_ops = True
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_nonallocfree_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['resize', 'relocation', 'access_change', 'flag_change']
	label_series_with_app = True
	combine_ops = True
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_allocs_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['alloc']
	label_series_with_app = True
	combine_ops = False
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_frees_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['free']
	label_series_with_app = True
	combine_ops = False
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_resizes_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['resize']
	label_series_with_app = True
	combine_ops = False
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_relocations_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['relocation']
	label_series_with_app = True
	combine_ops = False
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_access_changes_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['access_change']
	label_series_with_app = True
	combine_ops = False
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_flag_changes_datafn(auxdata, plot_event, tgid, currentapp):
	desired_ops = ['flag_change']
	label_series_with_app = True
	combine_ops = False
	return vmaops_datafn(auxdata, plot_event, tgid, currentapp,
			desired_ops, label_series_with_app, combine_ops)

def vmaops_datafn(auxdata, plot_event, tgid, currentapp, desired_ops,
		label_series_with_app=True, combine_ops=False):
	tag = 'vmaops_datafn'

	vma = plot_event.vma
	if vma is None:
		return None

	# Skip this vma if it's for a shared lib, guard region, etc.
	# Are there any other special considerations that we have to
	# make for ignored vmas here (like in vmacount_datafn and
	# vm_size_datafn)? These are the vma-op possibilities that
	# are tracked below:
	#   alloc          map
	#   resize         remap
	#   relocation     remap
	#   access_change  remap
	#   flag_change    remap
	#   free           unmap
	# If any of these operations act on a shared-lib / guard /
	# shared-file vma, then they will be ignored here. One
	# possible weirdness that I see is if a vma is first allocated
	# as something that's ignored (e.g. r--pf for a shared lib) and
	# then is access_changed to something that's not ignored, it
	# will appear to be an access_change without a corresponding
	# alloc, but I think this case occurs rarely if ever. The opposite
	# occurs more frequently: something that was previously counted
	# (e.g. rw-pf for a shared lib) is access_changed to something
	# that's now ignored. In this case, the access_change will
	# never be counted, and additionally there will be an alloc
	# without a corresponding free.
	#   Ok, so this could be a little weird, and difficult to handle
	#   here because we don't do any tracking on unmaps at all.
	#   Just live with the weirdness I guess, or comment out the
	#   ignore_vma code here altogether for vmaops plots, depending
	#   on what we want to count exactly.
	if vm.ignore_vma(vma):
		debug_ignored(tag, ("ignoring vma {}").format(vma))
		return None

	# See extensive comments in consume_vma() about how each operation
	# is encoded, especially frees!
	# Look for explicit free operations first, then ignore any unmap
	# operations that are part of unmap-remap pairs and count the
	# remap operations.
	if vma.is_unmapped and vma.unmap_op == 'free':
		op = 'free'
		timestamp = vma.unmap_timestamp
	elif not vma.is_unmapped:
		op = vma.vma_op
		timestamp = vma.timestamp
	elif auxdata.veryfirstvma:
		# Create a point with the very first timestamp, so that every
		# plot will start from the same time (rather than every plot
		# starting from the first occurrence of a desired_op). This
		# difference is meaningful for apps with very short execution
		# times (e.g. it's misleading if the "frees" plot starts from
		# the time of the very first free, which could only be at
		# the very end of the execution).
		# Only check this condition after checking the op conditions
		# above, so that we don't skip the first op if it's meaningful
		# for desired_ops.
		# This works for the very first timestamp, but we should also
		# do this for the very last timestamp too (which we don't
		# know until plotting time... crap).
		op = 'veryfirst'
		timestamp = vma.timestamp
	else:
		print_debug(tag, ("vma_op={}, is_unmapped={}, unmap_op={}"
			"this is an unmap for an unmap-remap "
			"pair, so not counting this as an op.").format(vma.vma_op,
			vma.is_unmapped, vma.unmap_op))
		return None
	print_debug(tag, ("op={}, timestamp={}").format(op, timestamp))

	if op not in desired_ops and op != 'veryfirst':
		# Don't care about this op type
		return None
	elif combine_ops:
		# Combine all desired ops into one series
		op_orig = op
		op = 'combined'

	try:
		count = auxdata.opcounts[op]
	except KeyError:
		if op != 'veryfirst':   # usual case
			count = 0
		else:
			# This is the weird case: we want to create a 0 datapoint
			# for the op that this plot is tracking. If this plot is
			# tracking more than one op type, but is not combining
			# them, then this gets a bit weird... but this doesn't
			# actually happen right now.
			count = -1
			op = desired_ops[0]
			if len(desired_ops) > 1:
				print_warning(tag, ("very first op is not in desired_ops, "
					"but desired_ops has len > 1, so creating a 0 datapoint "
					"for just the first op {}").format(op))
	count += 1
	auxdata.opcounts[op] = count
	auxdata.veryfirstvma = False
	if count == 0:
		print_debug(tag, ("creating a 0 datapoint for op {} "
			"at timestamp {}").format(op, timestamp))

	point = datapoint()
	point.timestamp = timestamp
	point.count = count
	point.appname = currentapp
	if label_series_with_app:
		# No longer label seriesname with op - just with app name, and
		# then use op in the title.
		#seriesname = "{}-{}".format(currentapp, op)
		seriesname = "{}".format(currentapp)
	else:
		seriesname = op
		if combine_ops:
			# don't allow, would put all ops for all apps into one series.
			print_error(tag, ("invalid combination of label_series "
				"and combine_ops"))
			seriesname = op_orig

	# Return a list of (seriesname, datapoint) tuples:
	return [(seriesname, point)]

def vmaops_ts_plotfn(seriesdict, plotname, workingdir, title, ysplits=None):
	tag = 'vmaops_ts_plotfn'

	for appserieslist in seriesdict.values():
		if False:
			for S in appserieslist:
				for dp in S.data:
					print_debug(tag, ("debug: datapoint: count={}, "
						"timestamp={}").format(dp.count, dp.timestamp))
		normalize_appserieslist(appserieslist, True)
		if False:
			for S in appserieslist:
				for dp in S.data:
					print_debug(tag, ("debug: normalized: count={}, "
						"timestamp={}").format(dp.count, dp.timestamp))
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict)

	# Set up y-axis splits: set to None to just use one plot, or pass
	# a list of maximum y-values and plot_time_series will split up
	# the series into multiple plots, each plot with a different y-axis.
	#ysplits = []
	if ysplits is None:
		ysplits = [100, 1000, 10000, 100000]

	#title = ("VM operations over time").format()
	xaxis = "Execution time"
	yaxis = "Number of operations"
	return plot_time_series(plotdict, title, xaxis, yaxis, ysplits,
			logscale=False, cp_series=cp_series)

def vmaops_all_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"All VMA operations over time")
def vmaops_allocs_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA allocations over time")
def vmaops_frees_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA frees over time")
def vmaops_resizes_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA resizes over time", ysplits=[500, 5000])
def vmaops_relocs_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA relocations over time")
def vmaops_flag_changes_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA flag changes over time")
def vmaops_access_changes_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA permission changes over time")
def vmaops_nonallocfree_ts_plotfn(seriesdict, plotname, workingdir):
	return vmaops_ts_plotfn(seriesdict, plotname, workingdir,
			"VMA resizes, relocations, and permission changes")

##############################################################################
vmaops_all_plot = multiapp_plot('vma-ops-all',
		vmaops_auxdata, vmaops_all_ts_plotfn,
		vmaops_all_datafn, vmaops_resetfn)
vmaops_allocs_plot = multiapp_plot('vma-ops-allocs',
		vmaops_auxdata, vmaops_allocs_ts_plotfn,
		vmaops_allocs_datafn, vmaops_resetfn)
vmaops_frees_plot = multiapp_plot('vma-ops-frees', vmaops_auxdata,
		vmaops_frees_ts_plotfn, vmaops_frees_datafn, vmaops_resetfn)
vmaops_resizes_plot = multiapp_plot('vma-ops-resizes',
		vmaops_auxdata, vmaops_resizes_ts_plotfn,
		vmaops_resizes_datafn, vmaops_resetfn)
vmaops_relocations_plot = multiapp_plot('vma-ops-relocations',
		vmaops_auxdata, vmaops_relocs_ts_plotfn,
		vmaops_relocations_datafn, vmaops_resetfn)
vmaops_access_changes_plot = multiapp_plot('vma-ops-access_changes',
		vmaops_auxdata, vmaops_access_changes_ts_plotfn,
		vmaops_access_changes_datafn, vmaops_resetfn)
vmaops_flag_changes_plot = multiapp_plot('vma-ops-flag_changes',
		vmaops_auxdata, vmaops_flag_changes_ts_plotfn,
		vmaops_flag_changes_datafn, vmaops_resetfn)
vmaops_nonallocfree_plot = multiapp_plot('vma-ops-nonallocfree',
		vmaops_auxdata, vmaops_nonallocfree_ts_plotfn,
		vmaops_nonallocfree_datafn, vmaops_resetfn)

if __name__ == '__main__':
	print_error_exit("not an executable module")
