# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
from plotting.PlotEvent import PlotEvent
import brewer2mpl
import copy
import itertools
import numpy as np
import plotting.plots_style as style
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.ticker import FuncFormatter

CP_SERIESNAME = 'checkpoints'
  # special name to be used for series that contain datapoints for
  # CheckpointEvents.
TOTALKEY = '_ToTaL_'   # key that caller is unlikely to use...

PERMS_KEY_COLOR = {
		'r-xsa' : style.brewer_red,
		'r-xsf' : style.brewer_red,
		'r-xpa' : style.brewer_red,
		'r-xpf' : style.brewer_red,
		'rwxsa' : style.brewer_purple,
		'rwxsf' : style.brewer_purple,
		'rwxpa' : style.brewer_purple,
		'rwxpf' : style.brewer_purple,
		'rw-sa' : style.brewer_green,
		'rw-sf' : style.brewer_green,
		'rw-pa' : style.brewer_green,
		'rw-pf' : style.brewer_green,
		'r--sa' : style.brewer_orange,
		'r--sf' : style.brewer_orange,
		'r--pa' : style.brewer_orange,
		'r--pf' : style.brewer_orange,
		'---pa' : style.brewer_blue,
		'---pf' : style.brewer_blue,
	}

#######################################################################
'''
Class for a generic plot datapoint; series used by a multiapp_plot may
use this class for their datapoints, or they can use their own opaque
items. Neither multiapp_plot nor series depends on this class.
This class is effectively a "struct".
'''
class datapoint:
	tag = 'datapoint'

	# Generic fields - no plot will use all of them, so there is some
	# wasted memory space, but still seems like a good idea to have
	# this generic class that can be used in particular ways by each
	# plot.
	#   Maybe a better idea: have a generic datapoint interface that
	#   each particular plot must implement / subclass?
	xval = None
	yval = None
	timestamp = None
	count = None
	appname = None
	cp_name = None
	component = None

	def __init__(self):
		return

# Use this for plot_lineplot().
class SmallDatapoint:
	count = None
	def __init__(self, count=None):
		self.count = count
		return

# Returns a plot datapoint when given a PlotEvent for a cp_event. Later
# on, other functions can distinguish checkpoint datapoints from other
# datapoints by checking if point.cp_name is non-None.
def new_cp_datapoint(plot_event):
	tag = 'new_cp_datapoint'

	if not plot_event.cp_event:
		print_error(tag, ("plot_event's cp_event is None; will return "
			"None").format())
		return None

	# Note: for timeseries data, use timestamp, not xval! timestamp
	# is what's used for "normal" (non-checkpoint) datapoints.
	point = datapoint()
	point.timestamp = plot_event.cp_event.timestamp
	if plot_event.cp_event.cp_name:
		point.cp_name = plot_event.cp_event.cp_name
	else:
		point.cp_name = 'some-checkpoint'

	return point

##############################################################################
# Creates a new figure and sets some common parameters:
#   .pdf / .png size
#   Title
# The figure contains a single Subplot / Axes; the caller can get a
# reference to it with "plt.axes()". If the caller wishes to add
# multiple subplots, it can call .add_subplot() on the figure that
# is returned. (The caller probably should also delete the first
# axes that is present in the returned figure - see plot_time_series().
# Note that when the first axes is deleted, the title will be removed
# also).
# 
# Returns: a reference to the current figure. The figure number can be
#   obtained with fig.number, then if other operations create other
#   figures and make them current, the number can be used to get the
#   desired one.
def plot_setup_onesubplot(title, heightfactor, widthfactor):
	tag = 'plot_setup_onesubplot'

	fig = plot_setup_subplots(1, 1, heightfactor, widthfactor)
	ax = fig.get_axes()[0]

	# Assign the title to the one and only subplot:
	if title and len(title) > 1:
		# This works to create a centered title, but it doesn't work with
		# tight_layout() - it will get cropped, unlike a "standard" title.
		#   http://matplotlib.org/users/tight_layout_guide.html
		#plt.text(0.5, 1.03, title, horizontalalignment='center',
		#		transform = ax.transAxes,
		#		**style.title_kwargs)

		# This works pretty much the same as adding a new plt.text() as above,
		# but the title ends up a little closer to the top of the plot -
		# basically touching it. If this is a big problem, maybe the Text
		# reference that's returned from ax.set_title() can be moved up
		# directly? Or, it looks like the tight_layout() command takes a
		# rect argument whose top could be increased manually...
		ax.set_title(title, **style.title_kwargs)

	return fig

# Does NOT set the title - with multiple subplots, not sure what subplot
# axes (if any...) the title should belong to.
# Returns: the matplotlib.figure.Figure instance. The caller can get the
#   list of subplot axes by calling fig.get_axes() (which always returns
#   a 1d list, I think/hope), or can get a specific subplot axes by calling
#   fig.add_subplot(subplotrows, subplotcols, desiredsubplotnumber) again.
#   Note that this call must be made without a **kwargs argument! (see
#   the add_subplot() description: http://matplotlib.org/api/figure_api.
#   html#matplotlib.figure.Figure.add_subplot).
def plot_setup_subplots(subplotrows, subplotcols, heightfactor, widthfactor):
	tag = 'plot_setup_subplots'

	# fig is a matplotlib.figure.Figure instance. Every
	# matplotlib figure has a number; the doc for plt.figure() says
	# that "The figure objects holds this number in a number attribute."
	#   http://matplotlib.org/api/figure_api.html?highlight=figure#modu
	#   le-matplotlib.figure
	# The caller may wish to perform the following steps on the
	# returned figure:
	#   num = fig.number   # save for later... 
	#   ...
	#   currentfig = plt.figure(num)   # get reference to figure!
	#   plt.savefig(plot_fname)
	#   plt.close(currentfig)
	#     http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.close

	# Note: plt.subplots() would seem to be an easier way to setup
	# a figure with a specified number of subplot rows + cols, but it
	# doesn't take a figsize - ugh.
	# Also note: changing the scale factor to 1.0 at this point causes
	# the images (both png and pdf) to come out terrible - the "canvas"
	# shrinks and everything squishes together, and I have no idea why.

	scale_factor = 2.0
	figsize = (8*scale_factor*widthfactor, 6*scale_factor*heightfactor)
	  # Default figsize is (8,6): leads to an 800x600 .png image.
	fig = plt.figure(num=None, figsize=figsize, dpi=style.RASTER_DPI)
	  # num is the figure number, not the number of subplots.
	  # http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.figure

	for i in range(1, subplotrows*subplotcols + 1):
		fig.add_subplot(subplotrows, subplotcols, i)
		  # http://matplotlib.org/api/figure_api.html#matplotlib.
		  # figure.Figure.add_subplot

	'''
	(fig, ax_array) = plt.subplots(subplotrows, subplotcols)
	  # http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.subplots
	  # Note that format of ax_array differs depending on rows and cols...
	'''
	
	print_debug(tag, ("type(fig.get_axes()) is {}").format(
		type(fig.get_axes())))
	return fig

# Normalizes all of the series in the serieslist to each other. The
# total "width" of the horizontal / time / x-axis data is calculated
# across all of the series in the list, and then the datapoints for
# each series normalized in-place, resulting in x-coordinates that
# are all within the range [0..1]. Also, if alignright is True, then
# a final datapoint will be added all the way to the right of the
# time axis in every series.
def normalize_appserieslist(serieslist, alignright):
	tag = 'normalize_appserieslist'

	xmin = None
	xmax = None
	for S in serieslist:
		appmin = S.data[0].timestamp
		appmax = S.data[-1].timestamp
		if not xmin or appmin < xmin:
			xmin = appmin
		if not xmax or appmax > xmax:
			xmax = appmax
	
	width = xmax - xmin
	for S in serieslist:
		# To normalize each series, first subtract the minimum xval from
		# every point so that they all start at time 0, then divide the
		# point by the "width" of the execution time to get the "percent"
		# time, as a normalized value between 0 and 1.
		for i in range(len(S.data)):
			point = S.data[i]
			if width != 0:
				normalized = (point.timestamp - xmin) / width
			else:
				# If we have just one datapoint, put it in the middle
				# of the range...
				normalized = 0.5
			point.timestamp = normalized

		if alignright:
			if S.data[-1].timestamp < 1.0:
				lastpoint = copy.deepcopy(S.data[-1])
				lastpoint.timestamp = 1.0
				S.data.append(lastpoint)

	return

def percent0_formatter_func(n, pos=0):
	# This works to still use an integer percent label when log-scale is
	# enabled.
	return "{}%".format(int(round(n*100)))
	#return ("{0:.0f}%".format(n*100))

def percent1_formatter_func(n, pos=0):
	# Percentages: multiply by 100, *then* round to 1 decimal.
	return ("{:.1f}%".format(n*100))

def percent2_formatter_func(n, pos=0):
	# Percentages: multiply by 100, *then* round to 2 decimals.
	return ("{:.2f}%".format(n*100))

def log_to_standard_formatter_func(n, pos=0):
	# Show scale as 10, 100, 1000, etc., rather than 10^1, 10^2, etc.
	return "{}".format(int(n))

def billions_formatter_func(n, pos=0):
	divideby = 1000000000
	return ("{}".format(int(n/divideby)))

# Input:
#   A dict that maps series names to:
#     A list of datapoint objects, whose "timestamp" and "count" fields
#     are set! (the timestamp values in the list must be sorted?)
#   Title / labels
#   ysplits: y-axis values to split plot apart at. For example, a
#     ysplits list of [100, 1000] will cause this method to split the
#     series into three timeseries plots: one for series whose maximum
#     value is <= 100, one for series whose maximum value is between
#     101 and 1000, and one for series whose maximum value is greater
#     than 1000.
#   yax_units: display y-axis values as percentages rather than decimal.
#   cp_series: a series object containing datapoints for CheckpointEvents.
# Returns: a matplotlib.figure.Figure instance, or None if a figure
# could not be generated.
def plot_time_series(plotdict, title, x_axislabel, y_axislabel,
		ysplits, logscale=False, yax_units=None, cp_series=None):
	tag = 'plot_time_series'

	return plot_scatter_lineplot(plotdict, title, x_axislabel, y_axislabel,
			ysplits, logscale=logscale, yax_units=yax_units,
			cp_series=cp_series, is_timeseries=True, stepped=True)

# Simple lineplot, where each series in the plotdict has exactly
# one point per xlabel. The points in the lists held in the plotdict
# values must be datapoint or SmallDatapoint objects.
# Returns: a matplotlib.figure.Figure instance, or None if a figure
# could not be generated.
def plot_lineplot(plotdict, title, x_axislabel, y_axislabel, xlabels,
		ysplits, logscale=False, yax_units=None,
		#show_markers=True,
		hlines=None, vertical_xlabels=False):
	tag = 'plot_lineplot'

	if True:   # I think we always expect this:
		for (seriesname, pointlist) in list(plotdict.items()):
			if len(pointlist) != len(xlabels):
				print_unexpected(True, tag, ("series {} has "
					"{} points, but there are {} xlabels!").format(
					seriesname, len(pointlist), len(xlabels)))

	return plot_scatter_lineplot(plotdict, title, x_axislabel, y_axislabel,
			ysplits, logscale=logscale, yax_units=yax_units,
			xlabels=xlabels,
			#show_markers=show_markers,
			hlines=hlines,
			vertical_xlabels=vertical_xlabels)

# This method expects plotdict to be a mapping from series names to
# lists of datapoint objects. The datapoints must have their .count
# values set - these will be used for y-values in the plot. If
# use_timeseries is True, then the datapoints must also have their
# .timestamp values set - these will be used for x-values in the plot.
# Otherwise, the x-axis values are assumed to be discrete, and 
# the xlabels arg must be set to a list of labels, whose length
# matches the length of every series in the plotdict.
# For information about other args, see the comments above
# plot_time_series().
# Returns: a matplotlib.figure.Figure instance, or None if a figure
# could not be generated.
def plot_scatter_lineplot(plotdict, title, x_axislabel, y_axislabel,
		ysplits, logscale=False, yax_units=None, cp_series=None,
		is_timeseries=False, xlabels=None, stepped=False,
#		show_markers=False,
		hlines=None, vertical_xlabels=False):
	tag = 'plot_scatter_lineplot'

	if len(plotdict) == 0:
		print_warning(tag, ("not generating plot {} because no "
			"series were added!").format(title))
		return None

	y_axislabel_withunits = y_axislabel

	# To handle ysplits, we'll create a list of "seriesgroups," where
	# each seriesgroup is a map just like plotdict, but containing
	# only the series that fit into the split group.
	if ysplits is None:
		ysplits = []
	ysplits.append(sys.maxsize)
	  # http://docs.python.org/3.1/whatsnew/3.0.html#integers
	print_debug(tag, ("ysplits: {}").format(ysplits))
	seriesgroups = []
	splitmin = 0
	splitmax = 0
	for split in ysplits:
		splitmin = splitmax
		splitmax = split
		print_debug(tag, ("split group: [{}, {}]").format(splitmin, splitmax))

		group = dict()
		for (seriesname, pointlist) in list(plotdict.items()):
			maxcount = (max(pointlist, key=lambda dp: dp.count)).count
			if splitmin <= maxcount and maxcount <= splitmax:
				group[seriesname] = pointlist
				plotdict.pop(seriesname)   # remove non-grouped reference
				print_debug(tag, ("series {}: maxcount {}, added to "
					"split group [{}, {}]. {} series remaining in "
					"plotdict to put into groups").format(
					seriesname, maxcount, splitmin, splitmax,
					len(plotdict)))
		if len(group) > 0:
			seriesgroups.append(group)
		else:
			print_debug(tag, ("didn't insert any series into split "
				"group [{}, {}]").format(splitmin, splitmax))
	numgroups = len(seriesgroups)
	if numgroups < 1:
		print_error_exit(tag, ("something went wrong, numgroups = "
			"{}").format(numgroups))

	# Create a "stack" of plots - number of rows == numgroups. To display
	# this all clearly, increase heightfactor by some amount...
	# Note that plot_setup_subplots doesn't apply a title - need to do
	# it below!
	heightfactor = 1.0 + (numgroups-1) * 0.25
	widthfactor = 1.0
	fig = plot_setup_subplots(numgroups, 1, heightfactor, widthfactor)
	fignum = fig.number
	axlist = fig.get_axes()
	if len(axlist) != numgroups:
		print_error_exit(tag, ("unexpected: fig has {} axes, numgroups "
			"is {}").format(len(axlist), numgroups))

	makesubplotlegends = True
	legends = []

	# Now actually build the plot:
	groupnum = 0
	for group in seriesgroups:
		# 'steps-post' drawstyle: instead of connecting points like
		# (1,5) -> (2,6) with a direct (diagonal) line between them,
		# connect them using a step so that the time period between 1
		# and 2 is flat (effectively adds another point and creates
		# two line segments that are either horizontal or vertical:
		# (1,5) -> (2,5) -> (2,6)).
		#   http://matplotlib.org/api/artist_api.html#matplotlib.lines.
		#     Line2D.set_drawstyle
		# This is terrific for time-series plots; I should have added
		# this ages ago. For non-time-series line plots, default
		# drawstyle is probably what we want.
		if stepped:
			drawstyle = 'steps-post'
		else:
			drawstyle = 'default'

		# Call fig.add_subplot() to select the already-existing subplot
		# numbered by groupnum - plot_setup_subplots() already added the
		# subplots for us.
		groupnum += 1
		ax = fig.add_subplot(numgroups, 1, groupnum)
		firstgroup = True
		for (seriesname, pointlist) in sorted(group.items(),
				key = lambda s: s[0]):   # sort by seriesname
			#print_debug(tag, ("plotting series {} with {} points").format(
			#	seriesname, len(pointlist)))
			if is_timeseries:
				xvals = list(map(lambda dp: dp.timestamp, pointlist))
			else:
				if len(xlabels) > 0 and len(pointlist) != len(xlabels):
					print_error(tag, ("x-axis will have {} labels, "
						"but series {} only has {} points in it!"
						"xlabels={}, pointlist={}").format(len(xlabels),
						seriesname, len(pointlist), xlabels, pointlist))
					return None
				# Not sure if initial xval matters or not; if you want
				# to use 0.5 or something not 0 or 1, then use
				# np.arange().
				xvals = list(range(1, 1 + len(pointlist)))
			yvals = list(map(lambda dp: dp.count, pointlist))
			group_ymax = max(yvals)
			if firstgroup:
				#xmin = xvals[0]
				#xmax = xvals[-1]
				ymin = 0
				ymax = group_ymax
			else:
				#if xvals[0] < xmin:
				#	xmin = xvals[0]
				#if xvals[-1] > xmax:
				#	xmax = xvals[-1]
				if group_ymax > ymax:
					ymax = group_ymax

#			color = next(colors)
#			linestyle = next(linestyles)

			ts_kwargs = style.plot_ts_kwargs.copy()
			ts_kwargs['markersize'] = 10   # line width is 5 points
			app_kwargs = style.appname_to_kwargs(seriesname)
			ts_kwargs.update(app_kwargs)
			  # If ts_kwargs already has keys from app_kwargs, they
			  # will be overwritten in ts_kwargs.

#			if show_markers:
#				marker = '.'  # dot
#				#marker = '2'  # tri-up
#			else:
#				marker = None

			if len(pointlist) != len(xvals) or len(xvals) != len(yvals):
				print_error_exit(tag, ("mismatching lengths: pointlist "
					"{}, xvals {}, yvals {}").format(len(pointlist),
					len(xvals), len(yvals)))

			# Scatter plot:
			#   http://matplotlib.org/api/pyplot_api.html#matplotlib.
			#   pyplot.scatter
			# We really want to just visualize the line between scatter
			# points and ignore the individual points themselves...
			try:
				r = ts_kwargs['rasterized']
				#print_debug(tag, ("rasterized={}").format(r))
			except KeyError:
				print_unexpected(True, tag, ("rasterized not set "
					"in ts_kwargs"))
			ax.plot(xvals, yvals,
					label=seriesname,
					drawstyle=drawstyle,
					**ts_kwargs)

		# Checkpoints: if cp_series is not None, then add vertical lines
		# to every plot at the x-values (timestamps) kept in the series'
		# datapoints. See new_cp_datapoint() for the construction of
		# these points.
		if cp_series:
			print_debug(tag, ("{}: attempting to add {} checkpoint "
				"lines to axes").format(cp_series.seriesname,
				len(cp_series.data)))
			for point in cp_series.data:
				xtime = point.timestamp
				cp_name = point.cp_name
				ax.axvline(x=xtime, **style.cp_line_kwargs)

		if hlines != None and len(hlines) > 0:
			for yval in hlines:
				ax.axhline(y=yval, **style.hline_kwargs)
		
		bottomticks = 'on'   # 'off' / 'on'
		ax.tick_params(axis='x', top='off', bottom=bottomticks,
			width=style.plotconf['tickwidth'],
			length=style.plotconf['ticklength'],
			labelsize=style.plotconf['smallticklabelsize'],
			pad=style.plotconf['ticklabelpad'])
			  # http://matplotlib.org/api/axes_api.html#matplotlib.
			  #   axes.Axes.tick_params

		# Make sure to do this AFTER setting tick_params, or size will be
		# overwritten! UGH
		kwargs_copy = style.ticklabel_kwargs.copy()
		if vertical_xlabels:
			kwargs_copy['rotation'] = 'vertical'
			kwargs_copy['size'] = 32   # hard-code here for now...
		if is_timeseries:
			ax.set_xticklabels([], **kwargs_copy)
		else:
			ax.set_xticks(xvals)
			ax.set_xticklabels(xlabels, **kwargs_copy)

		if groupnum == numgroups:
			ax.set_xlabel(x_axislabel, **style.axislabel_kwargs)
#			ax.tick_params(axis='x', top='off', bottom=bottomticks,
#				labelsize=style.plotconf['smallticklabelsize'],
#				pad=style.plotconf['ticklabelpad'])
#			  # http://matplotlib.org/api/axes_api.html#matplotlib.
#			  #   axes.Axes.tick_params
#		else:
#			ax.tick_params(axis='x', top='off', bottom=bottomticks)

		# Add a dummy y-label, so that tight_layout() will leave room for
		# the real y-label we'll add later.
		ax.set_ylabel('dummy', **style.axislabel_kwargs)

		ax.tick_params(axis='y', right='off',
			labelsize=style.plotconf['ticklabelsize'],
			width=style.plotconf['tickwidth'],
			length=style.plotconf['ticklength'],
			pad=style.plotconf['ticklabelpad'])
		  # Turns off ticks on the right y-axis. Passing
		  # **style.ticklabel_kwargs here doesn't change the tick label
		  # size, no idea why.
		if logscale:
			# Make sure that this comes before the formatter stuff
			# below, otherwise the specified formats will be overriden.
			ax.set_yscale('log')
		if yax_units == 'percents':
			# todo: use Python closures to do this much more effectively...
			#   (see get_active_vmas() method).
			if group_ymax < 0.01:
				ax.yaxis.set_major_formatter(
						FuncFormatter(percent2_formatter_func))
			elif group_ymax < 0.1:
				ax.yaxis.set_major_formatter(
						FuncFormatter(percent1_formatter_func))
			else:
				ax.yaxis.set_major_formatter(
						FuncFormatter(percent0_formatter_func))
			  # http://matplotlib.org/api/ticker_api.html#tick-formatting
			  # http://matplotlib.1069221.n5.nabble.com/formatting-axis-
			  #   to-percent-notation-td12709.html
		elif yax_units == 'billions':
			ax.yaxis.set_major_formatter(
					FuncFormatter(billions_formatter_func))
			y_axislabel_withunits = "{} (billions)".format(y_axislabel)

		# Create a dummy title for first subplot, so that tight_layout()
		# will leave room for the suptitle Text we'll add later.
		if groupnum == 1 and title and len(title) > 1:
			ax.set_title('dummy', **style.title_kwargs)

		# Zoom / bounds:
		if not is_timeseries:
			ax.autoscale_view(scalex=True, scaley=True)
		else:
			ax.autoscale_view(scalex=False, scaley=True)
		  # autoscale_view() seems to "zoom out" a bit from the plot in the
		  # same way that ax.set_ybound(0, ymax * 1.1) does, but autoscale_view
		  # seems to do it in a nice way - e.g. it ensures that the top of the
		  # plot ends exactly on a major tick.
		  # autoscale_view() doesn't seem to have any impact on the legend -
		  # putting on or the other first looks the same.
		  # Why did I use scalex=False for timeseries? I don't remember...

		force_yaxis_zero = True
		if force_yaxis_zero:
			ax.set_ylim(bottom=0)

		# Calling tight_layout() with the default padding causes the figure
		# view to be adjusted so that all of the labels and titles (as long
		# as they are set using the default methods, and not by adding
		# additional Text items manually) to fit in the view, which is great.
		# If it seems too tight, then use a larger pad; the default is 1.08,
		# which is the "fraction of the font size" to add as padding, so it
		# may need to be increased quite a bit.
		# Also note that tight_layout() operates on each subplot, not on
		# the entire figure...
		# More details:
		#   http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.
		#     tight_layout
		#   http://matplotlib.org/api/tight_layout_api.html
		plt.tight_layout(pad=2.5)

		# Calling ax_set_ylabel(y_axislabel) for middle plot doesn't
		# work here - the space between the subplots is just expanded
		# so that the label doesn't overlap the top + bottom plots.
		ax.set_ylabel('', **style.axislabel_kwargs)  # clear dummy label
		if groupnum == 1 and title and len(title) > 1:
			ax.set_title('', **style.title_kwargs)

		if makesubplotlegends:
			# Legend:
			#   http://matplotlib.org/api/pyplot_api.html#matplotlib.
			#   pyplot.legend
			#   http://matplotlib.org/api/legend_api.html#matplotlib.
			#   legend.Legend
			#   http://matplotlib.org/examples/api/legend_demo.html
			#   http://matplotlib.org/examples/pylab_examples/
			#   annotation_demo.html
			#   http://matplotlib.org/users/legend_guide.html
			# Resizing the legend and the plot to fit in the same figure is
			# a real pain. Here's the general gist of this solution: first,
			# call tight_layout() to set up the plot axes nicely. Then,
			# generate a legend and draw it so that we know how large its
			# window / frame needs to be. Then, "shrink" the plot axes by
			# this amount, so that the axes and the legend will both fit in
			# the figure.
			#
			# I think this answer was what eventually led me to implement
			# this resizing solution:
			#   http://stackoverflow.com/a/15873174/1230197
			# This answer may also be viable - I didn't try it, but it involves
			# resizing when save_fig() is called.
			#   http://stackoverflow.com/a/10154763/1230197
			# Other links I looked at:
			#   http://stackoverflow.com/a/4701285/1230197

			# To position legend vertically centered, to the right + outside
			# of the axes: use bbox_to_anchor to set the anchor all the way
			# to the right (1) and halfway up (0.5) from the axes' 0,0
			# (lower-left corner, I think). Then, locate the legend to
			# the 'center left' of that...
			# NOTE: must call plt.draw() before legend.get_window_extent() or
			# other legend display methods will work! However, with multiple
			# subplots, calling plt.draw() will undo any shrinking done for
			# previous subplots - so, set up the legends here, then do the
			# shrinking again in another loop later!
			legend = ax.legend(loc='center left', bbox_to_anchor=(1, 0.5),
					**style.legend_line_kwargs)
			for label in legend.get_lines():
				label.set_linewidth(style.LINEWIDTH)
			plt.draw()
			  # What the hell - when plotting kbuild trace I started
			  # getting an exception from here:
			  #   OverflowError: Allocated too many blocks
			  # Why did this start happening all of a sudden? No idea -
			  # I tried reverting a few recent changes, but I haven't
			  # done anything recently that should affect the number of
			  # points that kbuild is plotting.
			  # Some further investigation reveals that this exception
			  # is thron from the matplotlib rasterization code - for
			  # now, decrease DPI from 400 to 300 to make it go away
			  # (but 400 DPI did work for a few runs for building
			  # allplots a couple days ago...).
			legends.append(legend)

		firstgroup = False

	if makesubplotlegends:
		# Need to do this separately, outside of the loop above: the
		# makesubplotlegends code above calls plt.draw(), which is
		# necessary but un-does the changes here for earlier subplots
		# if we call it again for later subplots.
		for i in range(0, len(fig.get_axes())):
			ax = fig.get_axes()[i]
			legend = legends[i]

			# We want to shrink the axes/plot by the width of the legend
			# window. However, the mechanism for shrinking, ax.set_position(),
			# uses different coordinates than the window/display coordinates.
			# So, calculate the portion of the ax-width that the legend-width
			# constitutes, then shrink the position box by 1 minus that.
			# Right?
			# Once we've re-set the position of the axes, we don't need to
			# re-draw the legend - it's still bound to the anchor on the
			# right of the axes, so it also moves.
			axwindow = ax.get_window_extent()
			legendwindow = legend.get_window_extent()
			#print_debug(tag, ("legend: axwindow {}x{}, legend "
			#	"window{}x{}").format(
			#	axwindow.width, axwindow.height,
			#	legendwindow.width, legendwindow.height))
			portion = float(legendwindow.width / axwindow.width)
			box = ax.get_position()
			ax.set_position(
				[box.x0, box.y0, box.width * (1 - portion), box.height])
			#print_debug(tag, ("legend: portion={}, 1-portion = {}, "
			#	"box.width was {}, now box.width should be {}").format(
			#	portion, 1 - portion, box.width,
			#	box.width * (1 - portion)))
	
	# Add Text instances for title and for y-axis label here, after all
	# of the tight_layout() calls have been made (with dummy title +
	# labels to leave space), because tight_layout() doesn't account
	# for Texts added directly to the figure. Adding the title and
	# y-axis labels directly to the axes above doesn't work, the layout
	# will not be centered across all of the subplots correctly.
	# Don't try to use fig.suptitle() here, just use fig.text() - suptitle
	# works for one label, but can't create multiple suptitles.
	# Unfortunately some of these offsets are hard-coded at the moment :(
	#   http://matplotlib.org/api/figure_api.html#matplotlib.figure.
	#   Figure.text
	#   http://matplotlib.org/api/artist_api.html#matplotlib.text.Text
	t_kwargs = style.title_kwargs.copy()
	t_kwargs['horizontalalignment'] = 'center'
	t_kwargs['verticalalignment'] = 'top'  # not 'top'!
	xpos = 0.5     # horizontally centered
	ypos = 0.995   # top of figure is 1.0
	title_Text = fig.text(xpos, ypos, title, **t_kwargs)

	ylabel_kwargs = style.axislabel_kwargs.copy()
	ylabel_kwargs['horizontalalignment'] = 'center'
	ylabel_kwargs['verticalalignment'] = 'center'  # not 'top'!
	ylabel_kwargs['rotation'] = 'vertical'
	xpos = 0.033
	ypos = 0.5     # vertically centered
	ylabel_Text = fig.text(xpos, ypos, y_axislabel_withunits, **ylabel_kwargs)

	return fig

def plot_stacked_columns(category_labels, plotdict, title,
		x_axislabel, y_axislabel, sortcolumns='ascending',
		logscale=False, yax_units=None, labels_on_xaxis=False,
		needs_legend=True, ysplits=None):
	tag = 'plot_stacked_columns'

	return plot_columns(category_labels, plotdict, title,
		x_axislabel, y_axislabel, sortcolumns=sortcolumns,
		logscale=logscale, yax_units=yax_units,
		arrangement='stacked', labels_on_xaxis=labels_on_xaxis,
		needs_legend=needs_legend, ysplits=ysplits)

def plot_sidebyside_columns(category_labels, plotdict, title,
		x_axislabel, y_axislabel, sortcolumns='ascending',
		logscale=False, yax_units=None, labels_on_xaxis=False,
		needs_legend=True):
	tag = 'plot_sidebyside_columns'

	return plot_columns(category_labels, plotdict, title,
		x_axislabel, y_axislabel, sortcolumns=sortcolumns,
		logscale=logscale, yax_units=yax_units,
		arrangement='sidebyside', labels_on_xaxis=labels_on_xaxis,
		needs_legend=needs_legend)

# Arguments:
#   category_labels: a list of labels for the categories that make
#     up the column. The 0th element in this list will be the
#     bottom of the stack or the left-most column for each app, then
#     the 1st element, and so on.
#   plotdict: a nested dictionary: the outer dict maps application
#     names to inner dicts, which map category labels to numeric
#     values. The application names (outer dict keys) will be used
#     as x-axis labels. If an application does not have a key for
#     a particular category label in its inner dictionary, 0 will
#     be used for the count.
#   sortcolumns: if set to 'descending', the columns will be sorted in
#     descending order from left-to-right on the plot. If set to
#     'ascending' or any other value, the columns will be sorted
#     in ascending order. If set to 'nosort', the columns will not
#     be sorted.
#   logscale: should y-axis be log-scale or not.
#   yax_units: display y-axis values as 'percents' or 'billions'.
#   arrangement: 'stacked' to stack up values for category_labels
#     into one column per app. 'sidebyside' to plot one column for
#     every category_labels value per app.
#   labels_on_xaxis: if true, then rather than putting the category
#     labels in a legend and drawing every column in a separate
#     color, all columns will be the same label, but the category
#     label will be drawn underneath every column.
#   ysplits: used for side-by-side plots to split up x-axis based on
#     y-values.
#
# Returns: a matplotlib.figure.Figure instance
def plot_columns(category_labels, plotdict, title,
		x_axislabel, y_axislabel, sortcolumns='ascending',
		logscale=False, yax_units=None, arrangement='sidebyside',
		labels_on_xaxis=False, needs_legend=True, ysplits=None):
	tag = 'plot_columns'

	y_axislabel_withunits = y_axislabel

	# Column / bar plot:
	#   http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.bar
	#   http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.bar
	#   http://matplotlib.org/mpl_examples/pylab_examples/barchart_demo.py
	#   http://matplotlib.org/users/tight_layout_guide.html
	#   http://matplotlib.org/faq/howto_faq.html#howto-subplots-adjust
	#   http://matplotlib.org/users/legend_guide.html

	# Augment the plotdict: add 0 values for any labels that are
	# missing, and add a 'total' category.
	for (appname, appdict) in plotdict.items():
		total = 0
		for label in category_labels:
			try:
				total += appdict[label]
			except KeyError:
				appdict[label] = 0
		appdict[TOTALKEY] = total
		#print_debug(tag, ("set {}-dict[{}] = {}").format(appname,
		#	TOTALKEY, appdict[TOTALKEY]))

	if ysplits == None:
		ysplits = []
	ysplits.append(sys.maxsize)

	'''
	seriesgroups = []
	if sortcolumns != 'nosort' and len(ysplits) > 1:
		splitmin = 0
		splitmax = 0
		for split in ysplits:
			splitmin = splitmax
			splitmax = split
			print_debug(tag, ("split group: [{}, {}]").format(
				splitmin, splitmax))

			group = dict()
			for (appname, appdict) in list(plotdict.items()):
				total = appdict[TOTALKEY]
				if splitmin <= total and total <= splitmax:
					group[seriesname] = pointlist
					plotdict.pop(seriesname)   # remove non-grouped reference
					print_debug(tag, ("series {}: total {}, added to "
						"split group [{}, {}]. {} series remaining in "
						"plotdict to put into groups").format(
						seriesname, total, splitmin, splitmax,
						len(plotdict)))
			if len(group) > 0:
				seriesgroups.append(group)
			else:
				print_debug(tag, ("didn't insert any series into split "
					"group [{}, {}]").format(splitmin, splitmax))
		numgroups = len(seriesgroups)
		if numgroups < 1:
			print_error_exit(tag, ("something went wrong, numgroups = "
				"{}").format(numgroups))

		fig = ...
	else:
		fig = plot_setup_onesubplot(title, 1.0, 1.0)
	fignum = fig.number
	'''
	
	fig = plot_setup_onesubplot(title, 1.0, 1.0)
	fignum = fig.number

	# tuples is a list of (appname, appdict) pairs...
	if sortcolumns == 'nosort':
		# "nosort" is essentially "random sort" - whatever order the
		# apps come out of the dict in.
		tuples = list(plotdict.items())
	else:
		# Arrange the plot data: sort by total
		tuples = list(sorted(plotdict.items(),
		                     key=lambda pair: pair[1][TOTALKEY]))
		if sortcolumns == 'descending':
			tuples = list(reversed(tuples))
	appnames = []
	appdicts = []
	for (appname, appdict) in tuples:
		appnames.append(appname)
		appdicts.append(appdict)
	ymax = max(map(lambda appdict: appdict[TOTALKEY], appdicts))
	#print_debug(tag, ("appnames: {}").format(appnames))
	#print_debug(tag, ("ymax: {}").format(ymax))

	# Build the plot: call plt.axes() to get a reference to the only
	# Axes in the figure, then pass the axes to the method for the
	# specified "arrangement".
	ax = plt.axes()
	if arrangement == 'stacked':
		majorcenters = apps_cols_stacked(appnames, appdicts, category_labels,
				ax, logscale)
		minorcenters = majorcenters
	elif arrangement == 'sidebyside':
		if labels_on_xaxis:
			# may want to make this an arg to plot_columns eventually...
			cycle_colors = False
		else:
			cycle_colors = True
		(minorcenters, majorcenters) = apps_cols_sidebyside(appnames,
				appdicts, category_labels, ax, logscale, cycle_colors)
	else:
		print_error(tag, ("invalid arrangement {}, returning no "
			"plot").format(arrangement))
		return None
	if (majorcenters is None or len(majorcenters) < 1 or
		minorcenters is None or len(minorcenters) < 1):
		print_error(tag, ("apps_cols {} failed, returning "
			"no plot").format(arrangement))
		return None

	ax.set_xlabel(x_axislabel, **style.axislabel_kwargs)
	xlabel_direction = 'vertical'
	kwargs_copy = style.ticklabel_kwargs.copy()
	if xlabel_direction == 'vertical':
		kwargs_copy['rotation'] = 'vertical'

	all_xticks = []
	all_xticklabels = []
	if arrangement == 'sidebyside' and labels_on_xaxis:
		for innerlist in minorcenters:
			all_xticks += innerlist   # appends each innerlist item
			all_xticklabels += category_labels
		#print_debug(tag, ("all_xticks={}").format(all_xticks))
		#print_debug(tag, ("all_xticklabels={}").format(all_xticklabels))
		ax.set_xticks(all_xticks)
		ax.set_xticklabels(all_xticklabels, **kwargs_copy)
		# TODO: plot the "major" (app) labels as well!
		#   Not sure I can do this using additional xticks (without
		#   overlapping "minor" xticks), but can probably just directly
		#   draw the labels using majorcenters...
	else:
		ax.set_xticks(majorcenters)
		ax.set_xticklabels(appnames, **kwargs_copy)
	ax.tick_params(axis='x', top='off', bottom='off',
		labelsize=style.plotconf['ticklabelsize'],
		pad=style.plotconf['ticklabelpad'])
	  # http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.tick_params

	#ax.set_yticklabels(ax.get_yticklabels(), **style.ticklabel_kwargs)  # no?
	ax.tick_params(axis='y', right='off',
		labelsize=style.plotconf['ticklabelsize'],
		width=style.plotconf['tickwidth'],
		length=style.plotconf['ticklength'],
		pad=style.plotconf['ticklabelpad'])
	  # Turns off ticks on the right y-axis. Passing **style.ticklabel_kwargs
	  # here doesn't change the tick label size, no idea why.
	if yax_units == 'percents':
		if ymax < 0.01:
			ax.yaxis.set_major_formatter(
					FuncFormatter(percent2_formatter_func))
		else:
			ax.yaxis.set_major_formatter(
					FuncFormatter(percent1_formatter_func))
	elif yax_units == 'billions':
		ax.yaxis.set_major_formatter(
				FuncFormatter(billions_formatter_func))
		y_axislabel_withunits = "{} (billions)".format(y_axislabel)
	elif logscale:
		ax.yaxis.set_major_formatter(
				FuncFormatter(log_to_standard_formatter_func))

	ax.set_ylabel(y_axislabel_withunits, **style.axislabel_kwargs)

	ax.autoscale_view(scalex=False, scaley=True)
	  # autoscale_view() seems to "zoom out" a bit from the plot in the
	  # same way that ax.set_ybound(0, ymax * 1.1) does, but autoscale_view
	  # seems to do it in a nice way - e.g. it ensures that the top of the
	  # plot ends exactly on a major tick.
	  # Don't scalex, or margin on far-left and far-right of bars is lost.

	# Calling tight_layout() with the default padding causes the figure
	# view to be adjusted so that all of the labels and titles (as long
	# as they are set using the default methods, and not by adding
	# additional Text items manually) to fit in the view, which is great.
	# If it seems too tight, then use a larger pad; the default is 1.08,
	# which is the "fraction of the font size" to add as padding, so it
	# may need to be increased quite a bit.
	# More details:
	#   http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.tight_layout
	#   http://matplotlib.org/api/tight_layout_api.html
	plt.tight_layout(pad=2.5)

	# Legend:
	#   http://matplotlib.org/api/pyplot_api.html#matplotlib.
	#   pyplot.legend
	#   http://matplotlib.org/api/legend_api.html#matplotlib.
	#   legend.Legend
	#   http://matplotlib.org/examples/api/legend_demo.html
	#   http://matplotlib.org/examples/pylab_examples/
	#   annotation_demo.html
	#   http://matplotlib.org/users/legend_guide.html
	# Resizing the legend and the plot to fit in the same figure is
	# a real pain. Here's the general gist of this solution: first,
	# call tight_layout() to set up the plot axes nicely. Then,
	# generate a legend and draw it so that we know how large its
	# window / frame needs to be. Then, "shrink" the plot axes by
	# this amount, so that the axes and the legend will both fit in
	# the figure.
	#
	# I think this answer was what eventually led me to implement
	# this resizing solution:
	#   http://stackoverflow.com/a/15873174/1230197
	# This answer may also be viable - I didn't try it, but it involves
	# resizing when save_fig() is called.
	#   http://stackoverflow.com/a/10154763/1230197
	# Other links I looked at:
	#   http://stackoverflow.com/a/4701285/1230197

	if len(category_labels) > 1 and needs_legend:
		# This legend stuff was first figured out in plot_scatter_lineplot(),
		# then copied here.
		# To position legend vertically centered, to the right + outside
		# of the axes: use bbox_to_anchor to set the anchor all the way
		# to the right (1) and halfway up (0.5) from the axes' 0,0
		# (lower-left corner, I think). Then, locate the legend to
		# the 'center left' of that...
		# NOTE: must call plt.draw() before legend.get_window_extent() or
		# other legend display methods will work! However, with multiple
		# subplots, calling plt.draw() will undo any shrinking done for
		# previous subplots - so, set up the legends here, then do the
		# shrinking again in another loop later!
		legend = ax.legend(loc='center left', bbox_to_anchor=(1, 0.5),
				**style.legend_cols_kwargs)
		for label in legend.get_lines():
			label.set_linewidth(style.LINEWIDTH)
		plt.draw()

		# We want to shrink the axes/plot by the width of the legend
		# window. However, the mechanism for shrinking, ax.set_position(),
		# uses different coordinates than the window/display coordinates.
		# So, calculate the portion of the ax-width that the legend-width
		# constitutes, then shrink the position box by 1 minus that.
		# Right?
		# Once we've re-set the position of the axes, we don't need to
		# re-draw the legend - it's still bound to the anchor on the
		# right of the axes, so it also moves.
		axwindow = ax.get_window_extent()
		legendwindow = legend.get_window_extent()
		#print_debug(tag, ("legend: axwindow {}x{}, legend "
		#	"window{}x{}").format(
		#	axwindow.width, axwindow.height,
		#	legendwindow.width, legendwindow.height))
		portion = float(legendwindow.width / axwindow.width)
		box = ax.get_position()
		ax.set_position(
			[box.x0, box.y0, box.width * (1 - portion), box.height])
		#print_debug(tag, ("legend: portion={}, 1-portion = {}, "
		#	"box.width was {}, now box.width should be {}").format(
		#	portion, 1 - portion, box.width,
		#	box.width * (1 - portion)))

	return fig

# Returns: a list of column centers, or None on error.
def apps_cols_stacked(appnames, appdicts, category_labels, axes, logscale):
	tag = 'apps_cols_stacked'

	if len(appnames) != len(appdicts):
		print_error(tag, ("mismatched lengths: appnames={}, "
			"appdicts={}").format(appnames, appdicts))
		return None

	reversed_labels = list(reversed(category_labels))
	numcols = len(appnames)
	centers = np.arange(numcols)
	if len(centers) > 1:
		# width should match distance between centers
		width = centers[1] - centers[0]
	else:
		width = 1.0
	margin = 0.25
	colwidth = width - margin

	for i in range(numcols):
		appname = appnames[i]
		appdict = appdicts[i]
		center = centers[i]
		#colors = style.brewer_list_six
		if len(category_labels) == 1:
			colors = [style.single_col_color]
		else:
			num_colors = max(len(category_labels) % 8, 3)
			colors = brewer2mpl.get_map('GnBu', 'sequential',
					num_colors).mpl_colors
		hatches = style.hatches_list

		# Build plots by plotting the top-most bar first, then
		# overlapping other bars on top of it.
		barheight = appdict[TOTALKEY]
		for j in range(len(reversed_labels)):
			# For legends: use same color for each label. Tell bar()
			# what label we're using so it can build the legend, but
			# only for the first app - it's not smart enough to
			# "coalesce" the legend labels across apps.
			color = colors[j % len(colors)]
			hatch = hatches[j % len(hatches)]
			label = reversed_labels[j]
			if i == 0:
				legendlabel = label
			else:
				legendlabel = None

			axes.bar(center, barheight, colwidth, align='center',
					bottom=0, log=logscale, label=legendlabel,
					color=color, hatch=hatch,
					edgecolor=style.brewer_almostblack,
					**style.plot_col_kwargs)
			  # http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.bar
			  # matplotlib bug (versions <= 1.3.0) when log=True:
			  #   http://stackoverflow.com/a/19047285/1230197
			  #   yep, my matplotlib version is/was 1.2.1 - ugh
			  # Workaround: set bottom=0 explicitly.

			labelheight = appdict[label]
			print_debug(tag, ("{} {}: bar from 0 to barheight {}, "
				"actual labelheight={}").format(
				appname, label, barheight, labelheight))
			barheight -= labelheight

		if barheight != 0:
			print_unexpected(True, tag, ("barheight = {} after label "
				"loop - entire stack not plotted?").format(
				barheight))

	return centers

# On success, returns a tuple with these elements:
#   A nested list: for each app, contains a list of the "minor" centers
#     of the columns plotted for that app.
#   A list of the "major" centers (across all of the columns for an app).
# On error, returns None.
def apps_cols_sidebyside(appnames, appdicts, category_labels, axes,
		logscale, cycle_colors):
	tag = 'apps_cols_sidebyside'

	if len(appnames) != len(appdicts):
		print_error(tag, ("mismatched lengths: appnames={}, "
			"appdicts={}").format(appnames, appdicts))
		return (None, None)

	numapps = len(appnames)
	numcols_perapp = len(category_labels)
	colwidth = 0.5   # arbitrary?
	appwidth = colwidth * numcols_perapp
	margin = appwidth / 4.0
	appwidth += margin
	start = margin + appwidth/2   # arbitrary?
	appcenters = np.linspace(start, start + appwidth * numapps,
			num=numapps)
	#print_debug(tag, ("numapps={}, numcols_perapp={}, colwidth={}, "
	#	"appwidth={}, margin={}, appcenters={}").format(numapps,
	#	numcols_perapp, colwidth, appwidth, margin, appcenters))

	minorcenters = list()
	for i in range(numapps):
		appname = appnames[i]
		appdict = appdicts[i]
		if cycle_colors:
			num_colors = max(len(category_labels) % 8, 3)
			colors = brewer2mpl.get_map('GnBu', 'sequential',
					num_colors).mpl_colors
		else:
			colors = [style.single_col_color] * len(category_labels)
		#hatches = style.hatches_list
		hatches = [None] * len(category_labels)
		
		columncenters = list()
		appcenter = appcenters[i]
		colcenter = appcenter - (colwidth * (numcols_perapp / 2))
		#print_debug(tag, ("appname={}, appcenter={}").format(
		#	appname, appcenter))

		# Build plots by plotting the top-most bar first, then
		# overlapping other bars on top of it.
		for j in range(len(category_labels)):
			# For legends: use same color for each label. Tell bar()
			# what label we're using so it can build the legend, but
			# only for the first app - it's not smart enough to
			# "coalesce" the legend labels across apps.
			color = colors[j]
			hatch = hatches[j]
			label = category_labels[j]
			if i == 0:
				legendlabel = label
			else:
				legendlabel = None
			
			colheight = appdict[label]
			#print_debug(tag, ("{} column {}: colcenter={}, "
			#	"colheight={}").format(appname, j, colcenter, colheight))
			axes.bar(colcenter, colheight, colwidth, align='center',
					bottom=0, log=logscale, label=legendlabel,
					color=color, hatch=hatch,
					edgecolor=style.brewer_almostblack,
					**style.plot_col_kwargs)
			  # http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.bar
			  # matplotlib bug (versions <= 1.3.0) when log=True:
			  #   http://stackoverflow.com/a/19047285/1230197
			  #   yep, my matplotlib version is/was 1.2.1 - ugh
			  # Workaround: set bottom=0 explicitly.
			
			columncenters.append(colcenter)
			colcenter+= colwidth
		minorcenters.append(columncenters)

	return (minorcenters, appcenters)

# Arguments:
#   seriesdict: a mapping from string keys (which will be used as the
#     column ticks) to numeric values.
#   sortcolumns: if set to 'ascending', the columns will be sorted in
#     ascending order from left-to-right on the plot.
#   logscale: should y-axis be log-scale or not.
#   yax_units: display y-axis values as percentages rather than decimal.
# Returns: a matplotlib.figure.Figure instance
def plot_columns_old(seriesdict, title, x_axislabel, y_axislabel,
		sortcolumns=None, logscale=False, yax_units=None):
	tag = 'plot_columns_old'

	print_warning(tag, ("obsoleted by plot_stacked_columns; "
		"convert callers to that method instead!").format())

	y_axislabel_withunits = y_axislabel

	# Column / bar plot:
	#   http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.bar
	#   http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.bar
	#   http://matplotlib.org/mpl_examples/pylab_examples/barchart_demo.py
	#   http://matplotlib.org/users/tight_layout_guide.html
	#   http://matplotlib.org/faq/howto_faq.html#howto-subplots-adjust
	#   http://matplotlib.org/users/legend_guide.html

	fig = plot_setup_onesubplot(title, 1.0, 1.0)
	fignum = fig.number
	numcols = len(seriesdict)

	# Arrange the plot data:
	appnames = []
	yvals = []
	if sortcolumns:
		tuples = sorted(seriesdict.items(), key=lambda pair: pair[1])
	else:
		tuples = seriesdict.items()
	for (appname, vmacount) in tuples:
		appnames.append(appname)
		yvals.append(vmacount)
	centers = np.arange(numcols)
	ymax = max(yvals)
	print_debug(tag, ("appnames: {}").format(appnames))
	print_debug(tag, ("yvals: {}").format(yvals))

	# Build the plot:
	width = 1.0   # should match distance between centers
	margin = 0.25
	colwidth = width - margin
	color = style.brewer_blue
	hatch = None

	ax = plt.axes()   # get reference to the only Axes in fig.
	ax.bar(centers, yvals, colwidth, align='center',
			bottom=0, log=logscale, color=color, hatch=hatch,
			**style.plot_col_kwargs)
	  # http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.bar
	  # matplotlib bug (versions <= 1.3.0) when log=True:
	  #   http://stackoverflow.com/a/19047285/1230197
	  #   yep, my matplotlib version is/was 1.2.1 - ugh
	  # Workaround: set bottom=0 explicitly.

	ax.set_xlabel(x_axislabel, **style.axislabel_kwargs)

	kwargs_copy = style.ticklabel_kwargs.copy()
	if True:
		kwargs_copy['rotation'] = 'vertical'
	#ax.set_xticks(lefts + (width / 2))
	ax.set_xticks(centers)
	ax.set_xticklabels(appnames, **kwargs_copy)
	ax.tick_params(axis='x', top='off', bottom='off',
		labelsize=style.plotconf['ticklabelsize'],
		pad=style.plotconf['ticklabelpad'])
	  # http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.tick_params

	#ax.set_yticklabels(ax.get_yticklabels(), **style.ticklabel_kwargs)  # no?
	ax.tick_params(axis='y', right='off',
		labelsize=style.plotconf['ticklabelsize'],
		width=style.plotconf['tickwidth'],
		length=style.plotconf['ticklength'],
		pad=style.plotconf['ticklabelpad'])
	  # Turns off ticks on the right y-axis. Passing **style.ticklabel_kwargs
	  # here doesn't change the tick label size, no idea why.
	if yax_units == 'percents':
		if ymax < 0.01:
			ax.yaxis.set_major_formatter(
					FuncFormatter(percent2_formatter_func))
		else:
			ax.yaxis.set_major_formatter(
					FuncFormatter(percent1_formatter_func))
	elif yax_units == 'billions':
		ax.yaxis.set_major_formatter(
				FuncFormatter(billions_formatter_func))
		y_axislabel_withunits = "{} (billions)".format(y_axislabel)
	ax.set_ylabel(y_axislabel_withunits, **style.axislabel_kwargs)

	ax.autoscale_view(scalex=False, scaley=True)
	  # autoscale_view() seems to "zoom out" a bit from the plot in the
	  # same way that ax.set_ybound(0, ymax * 1.1) does, but autoscale_view
	  # seems to do it in a nice way - e.g. it ensures that the top of the
	  # plot ends exactly on a major tick.
	  # Don't scalex, or margin on far-left and far-right of bars is lost.

	# Calling tight_layout() with the default padding causes the figure
	# view to be adjusted so that all of the labels and titles (as long
	# as they are set using the default methods, and not by adding
	# additional Text items manually) to fit in the view, which is great.
	# If it seems too tight, then use a larger pad; the default is 1.08,
	# which is the "fraction of the font size" to add as padding, so it
	# may need to be increased quite a bit.
	# More details:
	#   http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.tight_layout
	#   http://matplotlib.org/api/tight_layout_api.html
	plt.tight_layout(pad=2.5)

	return fig

# The plot_fname should not have an extension yet - this function will
# save both .pdf and .png formats.
# This method should usually be called on any figures before creating
# the next plot; otherwise, the next plot may be drawn on top of the
# previous one!
def save_close_plot(fig, plot_fname_no_ext, pdffiles=None):
	tag = 'save_close_plot'

	# http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.figure
	# http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig
	# http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.close

	# Default matplotlib dpi for png files:
	#   >>> import matplotlib
	#   >>> print(matplotlib.rcParams['savefig.dpi'])
	#   100
	#   >>> matplotlib.matplotlib_fname()
	#   '/etc/matplotlibrc'
	# Does increasing dpi make pngs look reasonable for inclusion in
	# my tex / pdf document? Well, viewing just the image on my Ubuntu
	# machine, 400 dpi actually looks worse than 100 dpi.
	# According to http://tex.stackexchange.com/a/1209:
	#   If you have a line drawing and if you really must use raster
	#   files instead of vector graphics, then use very high-resolution
	#   PNG files. Something like 600 dpi is usually enough. It looks
	#   good when printed. It will look reasonably good on screen; there
	#   will be some softness, e.g. horizontal and vertical lines are not
	#   as sharp as you would like, but you can usually live with this
	#   solution fairly well.
	# But a warning if you try to increase the dpi further: when I tried
	# to open a 1000dpi png file on Ubuntu, my  machine became completely
	# unresponsive and I had to switch ttys to kill the process that
	# started swapping uncontrollably.

	# png is not a vector format, pdf is; need to use pdf for
	# paper-quality images (they're smaller file size anyway!)
	#   http://tex.stackexchange.com/a/10970
	#   http://tex.stackexchange.com/a/63922
	# However, when plotting time-series plots with tens or hundreds of
	# thousands of points, using pdf (or svg) vector format creates a
	# problem: when viewing the pdf (especially on my Mac), scrolling and
	# zooming takes FOREVER, because the viewer has to constantly recalculate
	# the vectors and whatnot. I eventually found a few other people
	# having this problem:
	#   http://www.astrobetter.com/slim-down-your-bloated-graphics/
	# Apparently each line (and other matplotlib Artist) can be explicitly
	# *rasterized* when it is plotted, so I updated my plot kwargs to
	# now always include this argument for time series plots. When
	# calling savefig here, we can then specify the dpi for the rasterized
	# part (and apparently we can also set it when calling figure()
	# initially; I'm not sure which one, if either, has an effect).
	#
	# Apparently we can also try to use ImageMagick to convert our vector
	# pdfs to raster pngs afterwards; however, when I tried this command
	# on my desktop, it took just under 30 minutes to complete:
	#   convert -density 600 vma-counts.pdf vma-counts-converted.png
	# So hopefully it doesn't come to this.
	#
	# Other possibly helpful links:
	#   http://stackoverflow.com/q/5609969/1230197
	#   http://stackoverflow.com/a/12627640/1230197
	#   https://github.com/keflavich/mpl_plot_templates/blob/master/
	#     mpl_plot_templates/adaptive_param_plot.py
	#   http://stackoverflow.com/q/5609969/1230197
	#   http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.contour
	#   http://tex.stackexchange.com/a/1209
	#   http://tex.stackexchange.com/a/10970

	currentfig = plt.figure(fig.number)
	  # make sure that matplotlib's current figure is set to this one!
	pdf_fname = "{}.pdf".format(plot_fname_no_ext)
	plt.savefig(pdf_fname, dpi=style.RASTER_DPI)
	  # Call savefig for the pdf first, before the png - I'm paranoid that
	  # the settings for rasterized etc. will be lost after one savefig
	  # call...
	#png_fname = "{}.png".format(plot_fname_no_ext)
	#plt.savefig(png_fname)
	if pdffiles:
		for pdff in pdffiles:
			pdff.savefig()
	plt.close(fig)
	  # don't forget, or next fig will be drawn over top of this one!
	  # Also, will lead to a memory leak if you don't call close():
	  # http://stackoverflow.com/a/741884/1230197

	return

# fname should contain complete path and filename, WITHOUT .pdf suffix!
# Returns a pdffile that should later be passed to close_pdffile().
def new_pdffile(fname):
	tag = 'new_pdffile'

	pdffile = PdfPages("{}.pdf".format(fname))

	return pdffile

def close_pdffile(pdffile):
	pdffile.close()
	return

# Looks in the seriesdict (which comes from a multiapp_plot object)
# for series with criteria matching what's expected for series 
# that contain checkpoint data. Currently, this criteria is that
# CP_SERIESNAME is used for the seriesname, but this could be changed
# in the future to e.g. look at the datapoints in the series to see
# if they have a cp_name set.
# Any found cp_series are REMOVED from the seriesdict, and a list of
# them is returned. If no cp_series are found, [] is returned. None
# is returned on error.
def remove_cp_series(seriesdict):
	tag = 'remove_cp_series'

	cp_series_list = []

	for appserieslist in seriesdict.values():
		i = 0
		length = len(appserieslist)
		while i < length:
			S = appserieslist[i]
			if S.seriesname == CP_SERIESNAME:
				cp_series_list.append(S)
				appserieslist.pop(i)
				print_debug(tag, ("removed cp_series '{}' from "
					"app {}'s serieslist, which now has {} "
					"series in it").format(S.seriesname,
					S.appname, len(appserieslist)))
				if len(appserieslist) == 0:
					print_unexpected(True, tag, ("length of "
						"appserieslist for app {} hit 0 after "
						"removing cp_series").format(S.appname))
				length -= 1
			else:
				i += 1

	return cp_series_list

# Searches through the appseriesdict (from a multiapp_plot object) and
# REMOVES all of the checkpoint series from it (using remove_cp_series() -
# see further comments above that method). If a single checkpoint
# series is found, it is returned for use in plotting, otherwise if
# no cp_series or multiple cp_series are found, None is returned.
# The caller must be aware that the appseriesdict is modified when
# calling this method!
def handle_cp_series(appseriesdict):
	tag = 'handle_cp_series'

	cp_series = None
	cp_series_list = remove_cp_series(appseriesdict)
	if cp_series_list is None:
		print_error(tag, ("remove_cp_series failed, will try to "
			"proceed...").format())
	elif len(cp_series_list) == 0:
		print_debug(tag, ("no cp_series found in appseriesdict"))
	elif len(cp_series_list) == 1:
		cp_series = cp_series_list[0]
		print_debug(tag, ("exactly one cp_series found in appseriesdict, "
			"will pass it to time series plot method").format())
	else:
		# In the future, we could perhaps try to coalesce the
		# checkpoints from multiple apps into one series and pass
		# them all to the time series method...
		print_debug(tag, ("found {} cp_series in appseriesdict, "
			"so won't pass any cp_series to plot method").format(
			len(cp_series_list)))

	return cp_series

# Takes a appseriesdict which has had its cp_series removed (by calling
# handle_cp_series() on it), then converts its lists of series into
# a plotdict that maps series names to lists of series datapoints.
# If scale is set to an appropriate xx_BYTES value (pjh_utils.py),
# then every datapoint will also be scaled by this value; set scale
# to None to disable scaling. Note that this scaling will also affect
# the appseriesdict argument, so this method should not be called
# more than once.
# Returns: a plotdict, suitable for passing to a timeseries plot
# method, or None on error.
def construct_scale_ts_plotdict(appseriesdict, scale=None,
		uselastpoint=False, usemax=False):
	tag = 'construct_scale_ts_plotdict'

	# Check argument validity. Is there an easier way to do this??
	specialargs = 0
	if scale:
		specialargs += 1
	if uselastpoint:
		specialargs += 1
	if usemax:
		specialargs += 1
	if specialargs > 1:
		print_error(tag, ("invalid args: scale={}, uselastpoint={}, "
			"usemax={}").format(scale, uselastpoint, usemax))
		return None

	plotdict = dict()
	for appserieslist in appseriesdict.values():
		for series in appserieslist:
			try:
				exists = plotdict[series.seriesname]
				# This may happen e.g. if you put multiple trace runs
				# from the same app into the same results directory
				# and try to generate plots for that directory...
				print_unexpected(True, tag, ("got multiple series "
					"with name {} - one for appname {}, one for a "
					"previous appname").format(series.seriesname,
					series.appname))
				seriesname = "{}-{}".format(series.appname, series.seriesname)
			except KeyError:
				seriesname = series.seriesname

			if len(series.data) < 1:
				print_error(tag, ("huh?: len(series.data) = {}?").format(
					len(series.data)))
				continue

			# From the datafn, the series' data list already contains a list
			# of tuples in the (x, y) format needed to plot a time series.
			# The x values are timestamps, the y values are the size of the
			# entire virtual address space. If scale is set, then modify
			# every datapoint here by dividing by the scale - better to do
			# this here, so that scale can be changed without having to
			# re-run analysis to re-get datafn data.
			if scale:
				print_debug(tag, ("Scaling: dividing every data "
					"point's count by {}").format(scale))
				for point in series.data:
					point.count /= scale

#			if ():
#				newseriesname = ...
#			else:
#				newseriesname = seriesname

			if usemax:
				# http://docs.python.org/3/library/functions.html?
				# highlight=max#max
				plotdict[seriesname] = (max(series.data,
				                key=lambda point: point.count)).count
			elif uselastpoint:
				# This is used for e.g. average miss rate: we just want
				# to get the last point in the series that has been
				# tracked over the application's entire execution. This
				# means that plotdict is no longer a timeseries plot,
				# but it works for the column plots methods too.
				plotdict[seriesname] = series.data[-1].count
			else:
				plotdict[seriesname] = series.data
	
	return plotdict

# Takes a list of active_vmas from some point in time during the trace
# (e.g. when the maximum VM size was allocated), and creates plot
# events from these vmas by simply wrapping a PlotEvent class around
# them.
# I'm not sure why I added a special process_active_vmas method pointer
# to every multiapp_plot, when it seems like this should always suffice
# (and then further processing can be done in the plot's datafn when
# it gets these vmas)...
#   Oh, well I see one reason why: if the plot we're building is not
#   going to have one point per vma (e.g. it's not a va-space plot
#   or a timeseries plot), then if we do the processing of vmas down
#   to smaller datapoints in the process_active_vmas method, then
#   the datafn will end up creating fewer series and datapoints, which
#   will save on serialization time + space.
# Returns: a list of PlotEvents, or None on error.
def wrap_active_vmas(auxdata, active_vmas, appname, app_pid):
	tag = 'wrap_active_vmas'

	plotevents = []
	for vma in active_vmas:
		plot_event = PlotEvent(vma=vma)
		plotevents.append(plot_event)
		
	return plotevents

##############################################################################

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)
