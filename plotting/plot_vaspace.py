# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.PlotEvent import PlotEvent
import plotting.plots_style as style
import itertools
import plotting.plots_common as plots
import trace.vm_common as vm

#import numpy as np
#import matplotlib
#matplotlib.use('Agg')
#import matplotlib.pyplot as plt
#from matplotlib.backends.backend_pdf import PdfPages
#from matplotlib.ticker import FuncFormatter

##############################################################################
# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Only use "constants".

class vaspace_auxdata:
	def __init__(self):
		self.num_processes = None
		return

def vaspace_resetfn(auxdata):
	auxdata.num_processes = None
	return

class VASpaceDatapoint:
	# "txln" == translation
	def __init__(self, seriesname, num_txln_entries):
		#self.seriesname = seriesname
		#self.num_txln_entries = num_txln_entries
		return

##############################################################################

# This method expects the plot_event to have its vma member set to a vma,
# with no other types of plot_events coming in.
def vaspace_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'vaspace_datafn'

	vma = plot_event.vma
	if not vma:
		print_error(tag, ("got a plot_event without a vma "
			"set").format())
		return None

	# The vaspace plot needs the vmas separated by their permissions
	# keys, so use the perms_key as the seriesname. The "datapoint"
	# that we return is just a reference to the whole vma - the plotfn
	# needs several fields from the vma.
	# We don't use the app name to construct the series name here
	# because this plot only really makes sense for a single app at
	# a time.
	seriesname = vma.perms_key

	return [(seriesname, vma)]

##############################################################################

def scale_addr(addr):
	#ADDR_SCALE_FACTOR =  1  # divide addrs to avoid signed int problems...
	ADDR_SCALE_FACTOR =  2  # divide addrs to avoid signed int problems...
	return int(addr / ADDR_SCALE_FACTOR)

def vaspace_plotfn(seriesdict, plotname, workingdir):
	tag = 'vaspace_plotfn'

	# This plot only makes sense for a single app at a time, so if
	# we have more than one app in the seriesdict, just return now.
	if len(seriesdict) > 1:
		print_debug(tag, ("skipping multiapp-plot, vaspace plot "
			"only makes sense for a single app.").format())
		return None

	all_pdf_name = "{}/vaspace_plots_collected".format(workingdir)
	all_pdf = plots.new_pdffile(all_pdf_name)
	pdffiles = [all_pdf]

	# seriesdict maps an app name to a list of series for that app.
	# There should be one series for every permissions key found
	# in the app's vmas. Sort the vmas in every series by start_addr
	# in preparation for plotting below.
	proc_min_addr = vm.MAX_ADDR64
	proc_max_addr = -1
	total_vmacount = 0
	appname = list(seriesdict.keys())[0]
	appserieslist = list(seriesdict.values())[0]
	for S in appserieslist:
		S.data = sorted(S.data, key=lambda vma: vma.start_addr)
		if S.data[0].start_addr < proc_min_addr:
			proc_min_addr = S.data[0].start_addr
		if S.data[-1].end_addr() > proc_max_addr:
			prox_max_addr = S.data[-1].end_addr()
		total_vmacount += len(S.data)
	print_debug(tag, ("creating address space plot for {} with "
		"{} total vmas").format(appname, total_vmacount))

	vma_start_key = lambda vma: vma.start_addr
	vma_end_key   = lambda vma: vma.end_addr()

	max_perm_value = len(vm.PERMS_KEYS)
	unscaled_min = proc_min_addr
	unscaled_max = proc_max_addr
	scaled_min = scale_addr(proc_min_addr)
	scaled_max = scale_addr(proc_max_addr)
	#print_debug(tag, ("all plots: unscaled range [{0}, {1}], scaled "
	#	"range [{2}, {3}]").format(hex(unscaled_min), hex(unscaled_max),
	#	hex(scaled_min), hex(scaled_max)))

	bar_kwargs       = style.plot_bar_kwargs.copy()
	axislabel_kwargs = style.axislabel_kwargs.copy()

	xticklabel_kwargs = dict()
	xticklabel_kwargs['size'] = 24
	yticklabel_kwargs = dict()
	yticklabel_kwargs['size'] = 32
	yticklabel_kwargs['family'] = 'monospace'

	# Loop and create multiple plots. It is impossible to plot the
	# process' entire virtual address space on one chart, because it
	# is way too wide.
	# Current strategy: plot everything, but only create plots that
	# are up to some number of GB wide.
	plot_count = 0
	#max_plot_width = MB_BYTES * 180   # 180 MB used for generals
	#max_plot_width = MB_BYTES * 360
	max_plot_width = GB_BYTES * 1
	left_addr = unscaled_min
	while True:
		#title = "{} virtual address space".format(appname)
		#fig = plots.plot_setup_onesubplot(title, 1.0, 1.0)
		fig = plots.plot_setup_onesubplot(None, 1.0, 1.0)
		fignum = fig.number

		# "Control" variables:
		#   left_addr: should be set at this point (when every plot
		#     iteration begins) to the start_addr of some "minimum"
		#     vma where this plot will begin.
		#   right_addr: the right-most address of this loop's plot;
		#     set purely as a function of left_addr.
		#   min_addr_this_plot: the minimum (left-most) address in
		#     this plot (always == left_addr?)
		#   max_addr_this_plot: the maximum (right-most) address where
		#     a vma ends in this plot; set while the plot is constructed.
		#   start_next_plot: tracked while the plot is constructed,
		#     then used to set left_addr for the next loop's plot.
		#     Must be set in such a way that large swaths of virtual
		#     address space are skipped over.

		right_addr = left_addr + max_plot_width - 1
		if right_addr > vm.MAX_ADDR64:
			right_addr = vm.MAX_ADDR64
		min_addr_this_plot = vm.MAX_ADDR64
		max_addr_this_plot = 0x0
		start_next_plot = vm.MAX_ADDR64
		#print_debug(tag, ("starting plotting loop for addr range up "
		#	"to [{0}, {1}] (width {2} GB); min_addr_this_plot = {3}, "
		#	"max_addr_this_plot = {4}").format(
		#	hex(left_addr), hex(right_addr),
		#	(right_addr - left_addr + 1) / GB_BYTES,
		#	hex(min_addr_this_plot), hex(max_addr_this_plot)))

		y_value = 0
		keys_with_spaces = []   # HACK to increase space btw. axis and label
		for key in vm.PERMS_KEYS:
			keys_with_spaces.append("{} ".format(key))
		y_labels = [""] + keys_with_spaces
		#y_labels = [""] + vm.PERMS_KEYS
		forced_wide_vma = False
		for perms_key in vm.PERMS_KEYS:
			# Make sure to do these steps even when we skip a
			# permission type:
			color = plots.PERMS_KEY_COLOR[perms_key]
			y_value += 1  # start at height 1!

			# Look for a series matching this perms_key; unfortunately
			# a linear search here, but there's not that many perms_keys,
			# probably not worth putting them into a dict.
			# From above: the items in a series' data list are vma
			# references, and we've already sorted every vmalist by
			# start_addr.
			vmalist = None
			for S in appserieslist:
				if S.seriesname == perms_key:
					vmalist = S.data
					break
			if vmalist is None or len(vmalist) == 0:
				print_debug(tag, ("{}: no vmas in list for perms key "
					"{} - continuing to next key").format(
					appname, perms_key))
				continue   # next perms_key
			print_debug(tag, ("{}: {} vmas in list for perms_key "
				"{}").format(appname, len(vmalist), perms_key))
			if True:
				for i in range(len(vmalist)):
					vma = vmalist[i]
					print_debug(tag, ("            [{}]: [{}, {}]").format(
						i, hex(vma.start_addr), hex(vma.end_addr())))

			# It looks like the x-axis for the scatter plot is represented
			# internally as a signed 64-bit int; when given an address
			# greater than 2^63 - 1, plt.savefig() barfs up a
			# "ValueError: math domain error" exception. When I set
			# a maximum value of 2^63 - 1 in the
			# address list, this error went away. So, for now, just truncate
			# anything greater than this value?
			#   Maybe makes more sense to divide entire x-axis by some
			#   amount in order to fit? Dividing by 2 might not be
			#   enough (the maximum address value would then still be
			#   2^63, which is juuuust greater than 2^63 - 1), so divide
			#   by 4?

			bar_kwargs['gid'] = "{0} {1}".format(y_value, perms_key)
			bar_kwargs['label'] = "{0} {1}".format(y_value, perms_key)

			# Ok, in this plot, we want to include vmas that start
			# beyond left_addr and end before right_addr. Along
			# the way, we need to set min_addr_this_plot,
			# max_addr_this_plot, and start_next_plot.

			# binarysearch returns the index of the greatest element
			# that is less than or equal to the target. If all of
			# the elements are greater than the target, then -1 is
			# returned.
			# Important: use different search keys (start-addr vs.
			# end-addr) for left_idx and right_idx - this ensures
			# that we don't try to split vmas across plots. Special
			# case below for vmas that are wider than max_plot_width.
			# So, if all of the vmas in vmalist are greater than
			# both left_addr AND right_addr, then both left_idx
			# and right_idx will be -1, and we'll skip the while
			# loop entirely below.
			left_idx = binarysearch(vmalist, left_addr,
			                        vma_start_key, exact=False)
			right_idx = binarysearch(vmalist, right_addr,
			                         vma_end_key, exact=False)
			if left_idx < 0:
				# No vmas found that start before left_addr, so all
				# vmas must start to the right of left_addr.
				print_debug(tag, ("forcing left_idx from {} to "
					"0").format(left_idx))
				left_idx = 0
			elif vmalist[left_idx].start_addr != left_addr:
				# If we didn't get an exact match from the search,
				# then left_idx points to the last vma whose start_addr
				# is less than left_addr; we want to start from the
				# next vma, the first one whose start_addr is greater
				# than left_addr.
				print_debug(tag, ("vmalist[{}].start_addr {} "
					"doesn't exactly match left_addr {}, so "
					"incrementing left_idx to {}").format(
					left_idx, hex(vmalist[left_idx].start_addr),
					hex(left_addr), left_idx + 1))
				left_idx += 1
			#if right_idx < 0:
			#if right_idx < left_idx:
			if right_idx < left_idx and left_idx < len(vmalist):
				if right_idx != left_idx - 1:   # sanity check
					print_error_exit(tag, ("unexpected: right_idx={}, "
						"but left_idx={}").format(right_idx, left_idx))

				# All vmas end to the right of right_addr, which
				# usually means that we don't want to include any
				# of them in this plot. However, if the vma that
				# left_idx is pointing at is larger than
				# max_plot_width AND its start_addr is the same
				# as the left_addr (e.g. it will definitely be
				# the left-most vma in *this* plot), then
				# plot it in this (its own) plot, no matter how
				# big it is.
				# Push out right_addr so that sanity checks below
				# don't fail.
				if (vmalist[left_idx].length > max_plot_width and
					vmalist[left_idx].start_addr == left_addr):
					right_idx = left_idx
					forced_wide_vma = True
					print_debug(tag, ("hit a vma at exactly left_addr "
						"= {} whose length is "
						"greater than max_plot_width {}; setting "
						"right_idx = left_idx so that it will be "
						"plotted in its own plot, and right_addr "
						"remains {}. vma: {}").format(hex(left_addr),
						pretty_bytes(max_plot_width),
						hex(right_addr), vma))
			#elif vmalist[right_idx].end_addr() == right_addr:
			#	# If we had an exact match for the right_addr, 
			#	# then we still want to include it - I think
			#	# there's no special case here.
			print_debug(tag, ("left-right addrs [{}, {}]; got "
				"left_idx={}, right_idx={}").format(hex(left_addr),
				hex(right_addr), left_idx, right_idx))

			idx = left_idx
			while idx <= right_idx:
				if idx >= len(vmalist):
					print_debug(tag, ("  idx hit len(vmalist) {}").format(
						idx))
					break
				vma = vmalist[idx]
				idx += 1
				print_debug(tag, ("  adding vmalist[{}] = [{}, {}] "
					"to this plot").format(idx-1, hex(vma.start_addr),
					hex(vma.end_addr())))

				# Remember, we're setting these across all perms_keys
				# in the plot, not just across the vmas within this
				# perms_key / vmalist!
				if vma.start_addr < min_addr_this_plot:
					min_addr_this_plot = vma.start_addr
				if vma.end_addr() > max_addr_this_plot:
					max_addr_this_plot = vma.end_addr()

				# Everything that gets plotted should be scaled
				# (see comments above)
				left = scale_addr(vma.start_addr)
				width = (scale_addr(vma.start_addr + vma.length) -
				         scale_addr(vma.start_addr))
				plots.plt.barh(bottom=y_value, width=width, height=0.5,
						left=left, color=color,
						#linewidth=0.01,
						align='center', **bar_kwargs)

			# Make sure that we still enter this block even if we didn't
			# enter the while loop above.
			if idx < len(vmalist):
				# We stopped looping over the vmas in this list (or
				# never iterated over them at all) because they are
				# beyond the right_idx (not because we plotted the
				# last vma in the list). In this case, use idx (which
				# now should equal the first vma that we didn't plot)
				# to set start_next_plot.
				if vmalist[idx].start_addr < start_next_plot:
					start_next_plot = vmalist[idx].start_addr
					print_debug(tag, ("  set start_next_plot = vmalist"
						"[{}].start_addr = {}").format(idx,
						hex(start_next_plot)))
			else:
				print_debug(tag, ("  idx {} hit len(vmalist), so not "
					"considering this perms_key further for "
					"start_next_plot").format(idx))

			# loop again to next perms_key

		# (end for-perms_key loop)
		print_debug(tag, ("DONE WITH PERMS, range of plot is "
			"[{}, {}]").format(hex(min_addr_this_plot),
			hex(max_addr_this_plot)))

		# Sanity checks for plot splitting: if we forced a single wide
		# vma to take up all of this plot, then these checks are not
		# strict.
		strict = not forced_wide_vma
		if (min_addr_this_plot == vm.MAX_ADDR64 or
			max_addr_this_plot == 0x0):
			print_unexpected(strict, tag, ("invalid min_addr_this_plot {} "
				"or max_addr_this_plot {}").format(hex(min_addr_this_plot),
				hex(max_addr_this_plot)))
		if (min_addr_this_plot < left_addr or
			max_addr_this_plot > right_addr):
			print_unexpected(strict, tag, ("left-right range is [{}, {}], "
				"but addr_this_plot range is [{}, {}]").format(
				hex(left_addr), hex(right_addr),
				hex(min_addr_this_plot), hex(max_addr_this_plot)))

			#plots.plt.title(("{}: virtual address space layout ({} "
			#	"VMAs)").format(appname, total_vmacount),
			#	**style.title_kwargs)
			plots.plt.title(("{}: virtual address space layout").format(
				appname), **style.title_kwargs)

		scaled_min_this_plot = scale_addr(min_addr_this_plot)
		scaled_max_this_plot = scale_addr(max_addr_this_plot)
		
		# http://matplotlib.org/api/axis_api.html:
		# Bullshit: when width of plot [min_addr_this_plot,
		#   max_addr_this_plot] is just 1 page (4 KB), then pyplot
		#   apparently refuses to set the x-axis width correctly - the
		#   two ticks/labels overlap each other in the middle of the plot.
		#   I tried for an hour to fix this, but it's being ridiculous.
		ax = plots.plt.axes()
		#ax.autoscale(False)
		#ax.autoscale(enable=True, axis='x', tight=True)
		#ax.autoscale(enable=False, axis='x', tight=True)

		xtick_ticks = [scaled_min_this_plot, scaled_max_this_plot]
		xtick_labels = [str(hex(min_addr_this_plot)),
			str(hex(max_addr_this_plot))]   # labels are unscaled!
		width = max_addr_this_plot - min_addr_this_plot + 1   # unscaled!
		#print_debug(tag, ("this loop: determined plot address range "
		#	"[{0}, {1}] (width {2} MB)").format(hex(min_addr_this_plot),
		#	hex(max_addr_this_plot), width/MB_BYTES))
		if width > max_plot_width:
			print_unexpected(strict, tag, ("got width={} bytes, but "
				"max_plot_width is {} bytes!").format(width,
				max_plot_width))
		ax.set_xbound(scaled_min_this_plot, scaled_max_this_plot)
		ax.set_xlim(scaled_min_this_plot, scaled_max_this_plot)
		ax.set_xticks(xtick_ticks)
		ax.set_xticklabels(xtick_labels, **xticklabel_kwargs)
		ax.set_xlabel(("Address space (width {} MB)").format(
			width/MB_BYTES), **axislabel_kwargs)

		ax.set_ybound(0, max_perm_value)   # plus one?
		ax.set_ylim(0, max_perm_value)   # plut one?
		ax.set_ylabel("VMA permissions", **axislabel_kwargs)
		#print_debug(tag, ("numpy range: [{0}]. normal range: "
		#	"[{1}]").format(list(np.arange(max_perm_value)),
		#	list(range(max_perm_value))))
		ax.set_yticks(range(max_perm_value))   # plus one?
		ax.set_yticklabels(y_labels, **yticklabel_kwargs)
		#ax.tick_params(axis='both', labelsize='x-large')

		# Ugh
		#plots.plt.tight_layout()
		#ax.autoscale(enable=True, axis='x', tight=True)
		#ax.autoscale(enable=False, axis='x', tight=True)

		# Save plot:
		full_plot_fname = "{}/{}-{}-{}".format(workingdir, plotname,
				str(plot_count).zfill(2),
				"0x" + (hex(min_addr_this_plot)[2:]).zfill(16)
				#"0x" + (hex(max_addr_this_plot)[2:]).zfill(16)
				)
		plots.save_close_plot(fig, full_plot_fname, pdffiles)
		  # TODO: this is kind of a hack, all other plots do this
		  # in the multiapp_plot.complete() method...

		# Set up for next plot:
		plot_count += 1
		left_addr = start_next_plot
		if left_addr == vm.MAX_ADDR64:
			print_debug(tag, ("breaking out of plotting loop").format())
			break
		print_debug(tag, ("LOOPING AGAIN for next plot: "
			"left_addr={0}\n\n\n").format(hex(left_addr)))
	
	for pdff in pdffiles:
		pdff.close()
	
	return None

##############################################################################

# suffix should describe the point-in-time when this plot's data is
# being calculated.
def new_vaspace_plot(suffix, outputdir, proc_num, num_processes):
	#plotname = "vaspace-{}_{}-processes".format(suffix, num_processes)
	plotname = "vaspace-{}".format(suffix)
	new_vaspace_plot = multiapp_plot(plotname, vaspace_auxdata,
			vaspace_plotfn, vaspace_datafn, vaspace_resetfn,
			processfn=plots.wrap_active_vmas)
	new_vaspace_plot.set_workingdir(outputdir)
	new_vaspace_plot.auxdata.num_processes = num_processes
	  # probably shouldn't reach into opaque multiapp_plot.auxdata
	  # like this, but...
	return new_vaspace_plot

if __name__ == '__main__':
	print_error_exit("not an executable module")
