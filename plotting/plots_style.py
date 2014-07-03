# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

import brewer2mpl
import itertools
import sys
from util.pjh_utils import *

RASTER_DPI = 400
  # If pdf plots are still too unwieldy at 600 DPI, I think I got a
  # pretty good result with DPI = 400 (only on savefig(), didn't use
  # it on figure()). If "OverflowError" arises from matplotlib, try
  # reducing dpi to 300.
  # I ran some small plot generations and found that this parameter does
  # at least have an effect on runtime:
  #   600 DPI: real    0m27.670s
  #   400 DPI: real    0m15.906s
  # Plotting generals-stjohns-noptes with -a flag:
  #   450 DPI: real    52m21.993s
  #   500 DPI: real    56m31.333s   # no perf analysis
  #   600 DPI: killed by OOM killer after 59 minutes, with dmesg output:
  #     [165647.838917] [ pid ]   uid  tgid total_vm      rss nr_ptes
  #       swapents          oom_score_adj name
  #     [165647.839100] [18424] 18060 18424 15853329  6039287
  #       31046                   9766858             0 python3.3
  #     [165647.839103] Out of memory: Kill process 18424 (python3.3) score
  #       992 or      sacrifice child
  #     [165647.839106] Killed process 18424 (python3.3) total-vm:63413316kB,
  #       anon-rss: 24157144kB, file-rss:4kB
  #   500 DPI, with perf analysis: killed after 134m54.265s :(
  #   450 DPI, with perf analysis: ...
  # 450 DPI: makes generals PDF document unwieldy, it seems... try 400

# COLORS:
#   https://github.com/jiffyclub/brewer2mpl
#   http://bl.ocks.org/mbostock/5577023
#   http://blog.olgabotvinnik.com/post/58941062205/prettyplotlib-painlessly-create-beautiful-matplotlib

# Get qualitative color maps: each of these is a list, where the elements
# in the list can be directly passed as a color to matplotlib methods.
#   brewer2mpl.print_maps()
#   http://bl.ocks.org/mbostock/5577023
brewer_accent = brewer2mpl.get_map('Accent', 'qualitative',  8).mpl_colors
brewer_dark2  = brewer2mpl.get_map('Dark2',  'qualitative',  8).mpl_colors
brewer_paired = brewer2mpl.get_map('Paired', 'qualitative', 12).mpl_colors
brewer_set1   = brewer2mpl.get_map('Set1',   'qualitative',  9).mpl_colors
brewer_set2   = brewer2mpl.get_map('Set2',   'qualitative',  8).mpl_colors
brewer_set3   = brewer2mpl.get_map('Set3',   'qualitative', 12).mpl_colors
brewer_greys  = brewer2mpl.get_map('Greys',   'sequential',  9).mpl_colors

brewer_red    = brewer_set1[0]
brewer_blue   = brewer_set1[1]
brewer_green  = brewer_set1[2]
brewer_purple = brewer_set1[3]
brewer_orange = brewer_set1[4]
brewer_yellow = brewer_set1[5]
brewer_brown  = brewer_set1[6]
brewer_pink   = brewer_set1[7]
brewer_grey   = brewer_set1[8]
brewer_peach  = brewer_set2[1]
brewer_magenta     = brewer_accent[5]
brewer_darkpink    = brewer_dark2[3]
brewer_almostblack = brewer_greys[7]
brewer_black       = brewer_greys[8]

brewer_list_five = [
		brewer_blue,
		brewer_red,
		brewer_green,
		brewer_purple,
		#brewer_orange,
		brewer_darkpink,
	]
brewer_cycle_five = itertools.cycle(brewer_list_five)
brewer_list_six = [
		brewer_blue,
		brewer_red,
		brewer_green,
		brewer_purple,
		#brewer_orange,
		#brewer_brown,
		brewer_darkpink,
		brewer_yellow,
	]
brewer_cycle_six = itertools.cycle(brewer_list_six)

single_col_color = brewer_blue

# Repeat the characters to increase density of hatch pattern.
#   http://matplotlib.org/1.3.1/api/artist_api.html#matplotlib.patches.
#   Patch.set_hatch
hatches_list = [
		None,
		'////',
		#'\\\\\\\\',
		###'|||',
		#'-----',
		'++',
		#'xxx',
		###'ooo',
		#'OOO',
		###'...',
		###'***',
	]
hatches_cycle = itertools.cycle(hatches_list)

# Line styles:
#   http://matplotlib.org/api/artist_api.html#module-matplotlib.lines
#   http://matplotlib.org/examples/pylab_examples/line_styles.html
#     >>> from matplotlib.lines import Line2D
#     >>> Line2D.lineStyles.keys()
#     dict_keys(['', '-.', '--', '-', ':', 'None', ' '])
# Markers:
#   http://matplotlib.org/api/markers_api.html#module-matplotlib.markers
#     >>> from matplotlib.lines import Line2D
#     >>> Line2D.markers.keys()
#     dict_keys(['v', 0, '4', 3, '2', '3', 'p', '1', '>', '<', 5, 2, '8', 'd', 'x', ' ', '.', 'o', ',', '*', '+', 'h', 's', None, 1, 6, '^', '_', 7, 'D', 'None', 4, '', '|', 'H'])

# Dash styles:
#   http://matplotlib.org/1.2.1/examples/pylab_examples/dash_control.html
# Unfortunately, some of the time-series plots zig and zag so much that
# any dashes with a "down" portion longer than the "up" portion end up
# just looking solid. This is dumb.
LINEWIDTH  = 7             # in "points"
dotted_linewidth = 4
dash_space = LINEWIDTH
dash_short = LINEWIDTH / 2
dash_long  = LINEWIDTH
dash_verylong = LINEWIDTH * 3
dash_short_seq = (dash_short, dash_space)
dash_long_seq  = (dash_long, dash_space)
#dash_short_seq = (dash_long, dash_space)
#dash_long_seq  = (dash_verylong, dash_space)

# Quick and dirty: create dicts that map application names to various
# drawing styles and properties that we want to be consistent across
# plots. A possible better way to do this is to set these properties
# along with each plot *series*, but at least this way the properties
# will remain the same across all executions (whether or not some
# applications are including or missing, etc.).
#
# According to the Axes.plot() documentation, the kwargs are Line2D
# properties, so I think we can specify a kwargs dict for each app
# here, then merge it in with the "global" kwargs we want to use
# for the plot (e.g. plot_kwargs) before passing it to ax.plot().
#   http://matplotlib.org/api/artist_api.html#matplotlib.lines.Line2D.set_linestyle
#   http://matplotlib.org/api/markers_api.html#module-matplotlib.markers
# Ugh: matplotlib currently only puts markers at datapoints, and not at
# evenly-spaced intervals along a line. This makes the markers on time-series
# plots look seriously crappy. For now I've disabled markers, and will
# just rely on colors; eventually, need to try one of these solutions
# though.
#   http://stackoverflow.com/a/17418500/1230197 - seems most promising
#   http://stackoverflow.com/a/5321382/1230197 - seems basic, not sure
#     it will help my situation
#   https://github.com/matplotlib/matplotlib/issues/346 - matplotlib
#     feature request for this
#
# What about Axes.bar()? We may want to set the facecolor and the hatch,
# but for the column plots I'm making, it may be best to have all
# of the columns be the same color. 
#   http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.bar
#   http://matplotlib.org/api/artist_api.html#matplotlib.patches.Patch.set_hatch

#brewer_cycle_five = itertools.cycle(brewer_list_five)

apache_kwargs = {
		'color'		: brewer_blue,
		#'color'     : brewer_set2[0],
		#'facecolor'	: brewer_blue,
		'linestyle'	: '-',
		#'marker'	: 'o',
		'linewidth'	: LINEWIDTH
	}
cass_kwargs = {
		'color'		: brewer_red,
		#'color'     : brewer_set2[1],
		#'facecolor'	: brewer_red,
		'linestyle'	: '-',
		#'marker'	: '^',
		'linewidth'	: LINEWIDTH
	}
chrome_kwargs = {
		'color'		: brewer_green,
		#'color'     : brewer_set2[2],
		#'facecolor'	: brewer_green,
		'linestyle'	: '-',
		#'marker'	: 's',
		'linewidth'	: LINEWIDTH
	}
dedup_kwargs = {
		'color'		: brewer_purple,
		#'color'     : brewer_set2[3],
		#'facecolor'	: brewer_purple,
		'linestyle'	: '-',
		#'dashes'	: dash_long_seq,
		#'marker'	: '*',
		'linewidth'	: LINEWIDTH
	}
ffox_kwargs = {
		'color'		: brewer_orange,
		#'color'     : brewer_set2[4],
		#'facecolor'	: brewer_orange,
		'linestyle'	: '-',
		#'marker'	: 'D',
		'linewidth'	: LINEWIDTH
	}
graph_kwargs = {
		'color'		: brewer_blue,
		#'color'     : brewer_set2[5],
		#'facecolor'	: brewer_blue,
		'dashes'	: dash_long_seq,
		#'marker'	: 'o',
		'linewidth'	: LINEWIDTH
	}
proxy_kwargs = {
		'color'		: brewer_red,
		#'color'     : brewer_set2[6],
		#'facecolor'	: brewer_red,
		'dashes'	: dash_long_seq,
		#'marker'	: '^',
		'linewidth'	: LINEWIDTH
	}
hello_kwargs = {
		'color'		: brewer_green,
		#'color'     : brewer_set2[7],
		#'facecolor'	: brewer_green,
		'dashes'	: dash_long_seq,
		#'marker'	: 's',
		'linewidth'	: LINEWIDTH
	}
kbuild_kwargs = {
		'color'		: brewer_purple,
		#'color'     : brewer_set2[0],
		#'facecolor'	: brewer_purple,
		#'linestyle'	: '-',
		'dashes'	: dash_long_seq,
		#'marker'	: 'D',
		'linewidth'	: LINEWIDTH
	}
mcache_kwargs = {  # Avoid overlap with graph500
		'color'		: brewer_orange,
		#'color'     : brewer_set2[1],
		#'facecolor'	: brewer_orange,
		#'linestyle'	: ':',
		'dashes'	: dash_long_seq,
		#'marker'	: 'o',
		'linewidth'	: LINEWIDTH
	}
mysql_kwargs = {
		'color'		: brewer_blue,
		#'color'     : brewer_set2[2],
		#'facecolor'	: brewer_blue,
		#'linestyle'	: ':',
		'dashes'	: dash_short_seq,
		#'marker'	: '^',
		'linewidth'	: dotted_linewidth
	}
office_kwargs = {
		'color'		: brewer_red,
		#'color'     : brewer_set2[3],
		#'facecolor'	: brewer_red,
		#'linestyle'	: ':',
		'dashes'	: dash_short_seq,
		#'marker'	: 's',
		'linewidth'	: dotted_linewidth
	}
python_kwargs = {
		'color'		: brewer_green,
		#'color'     : brewer_set2[4],
		#'facecolor'	: brewer_green,
		#'linestyle'	: ':',
		'dashes'	: dash_short_seq,
		#'marker'	: '*',
		'linewidth'	: dotted_linewidth
	}
redis_kwargs = {
		'color'		: brewer_purple,
		#'color'     : brewer_set2[5],
		#'facecolor'	: brewer_purple,
		#'linestyle'	: ':',
		'dashes'	: dash_short_seq,
		#'marker'	: 'D',
		'linewidth'	: dotted_linewidth
	}
hellostatic_kwargs = {
		'color'		: brewer_orange,
		#'color'     : brewer_set2[6],
		#'facecolor'	: brewer_orange,
		'dashes'	: dash_short_seq,
		#'marker'	: '*',
		'linewidth'	: dotted_linewidth
	}
other_kwargs = {
		'color'		: brewer_grey,
		#'color'     : brewer_set2[7],
		#'facecolor'	: brewer_grey,
		'linestyle'	: '-.',
		#'marker'	: 'o',
		'linewidth'	: LINEWIDTH
	}
appname_to_line_kwargs = {
		'apache'		: apache_kwargs,
		'cass'			: cass_kwargs,
		'chrome'		: chrome_kwargs,
		'dedup'			: dedup_kwargs,
		'ffox'			: ffox_kwargs,
		'graph'			: graph_kwargs,
		'proxy'			: proxy_kwargs,
		'hello'			: hello_kwargs,
		'hellostatic'	: hellostatic_kwargs,
		'kbuild'		: kbuild_kwargs,
		'mysql'			: mysql_kwargs,
		'mcache'		: mcache_kwargs,
		'office'		: office_kwargs,
		'python'		: python_kwargs,
		'redis'			: redis_kwargs,
		'other'			: other_kwargs,
	}

# Returns the kwargs dict for the specified app. For safety, currently
# returns a copy of the dict, so that the settings in this file are
# not modified during execution.
# The caller may wish to merge this dict into another dict using the
# dict.update() method, e.g.:
#   plot_kwargs.update(appname_to_kwargs('apache'))
# (in this example the copy is actually unnecessary, but...)
def appname_to_kwargs(appname):
	tag = 'appname_to_kwargs'
	try:
		print_debug(tag, ("found kwargs for appname={}").format(
			appname))
		app_kwargs = appname_to_line_kwargs[appname]
	except KeyError:
		print_warning(tag, ("no kwargs found for appname={}, using "
			"\"other\" kwargs").format(appname))
		app_kwargs = other_kwargs
	return app_kwargs.copy()

##############################################################################

orig_plotconf = {
		'titlesize'				:	34,
		'ticklabelsize'			:	24,
		'smallticklabelsize'	:	20,
		'tickwidth'				:	4,
		'ticklength'			:	12,
		'axislabelsize'			:	28,
		'legendsize'			:	24,
		'linewidth'				:	4,
		'ticklabelpad'			:	14,
			# space (in points) btw. label and axis: 4 not enough, 24 too much
	}
paper_plotconf = {
		'titlesize'				:	40,
		'ticklabelsize'			:	36,
		'smallticklabelsize'	:	20,
		'tickwidth'				:	4,
		'ticklength'			:	12,
		'axislabelsize'			:	36,
		'legendsize'			:	36,
		'ticklabelpad'			:	14,
			# space (in points) btw. label and axis: 4 not enough, 24 too much
	}
plotconf = paper_plotconf

plot_kwargs = {
		'visible'		: True,
	}

plot_ts_kwargs = plot_kwargs.copy()
plot_ts_kwargs['rasterized'] = True
  # http://matplotlib.org/api/artist_api.html#matplotlib.artist.
  #   Artist.set_rasterized
  # http://www.astrobetter.com/slim-down-your-bloated-graphics/

plot_col_kwargs = plot_kwargs.copy()
  # add more members specific to column plots if necessary

plot_bar_kwargs = plot_kwargs.copy()

ticklabel_kwargs = {
		# see http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.set_xticklabels
		# for other potentially useful kwargs, like small-caps, condensed /
		# stretched font, color, ...
		'size' : plotconf['ticklabelsize'],
	}
smallticklabel_kwargs = {
		'size' : plotconf['smallticklabelsize'],
	}
axislabel_kwargs = {
		'size' : plotconf['axislabelsize'],
	}
legend_cols_kwargs = {
		#'size' : plotconf['legendsize'],
		'fontsize'		: plotconf['legendsize'],
		'shadow'		: False,
		'handlelength'	: 0.8,
		'handletextpad'	: 0.5,
	}
legend_line_kwargs = {
		# http://matplotlib.org/api/axes_api.html#matplotlib.axes.Axes.legend
		# Can't specify linewidth here :(
		#'size' : plotconf['legendsize'],
		'fontsize'		: plotconf['legendsize'],
		'shadow'		: False,
		'handlelength'	: 1.3,
		'handletextpad'	: 0.5,
	}
title_kwargs = {
		#'size' : plotconf['titlesize'],
		'fontsize' : plotconf['titlesize'],
	}
cp_line_kwargs = {
		# http://matplotlib.org/api/artist_api.html#matplotlib.lines.Line2D
		'linestyle' : '-',
		'linewidth' : 3,
		#'color' : COLOR_BROWN
		'color' : 'brown'
	}
hline_kwargs = {
		# http://matplotlib.org/api/artist_api.html#matplotlib.lines.Line2D
		'linestyle' : '-',
		'linewidth' : 3,
		'color' : 'gray'
	}

##############################################################################

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)
