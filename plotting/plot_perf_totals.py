# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.plots_common import *
import collections

##############################################################################

# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Constant values are ok.

class totals_counts_auxdata:
	tag = 'totals_counts_auxdata'

	# Python simple queues: http://docs.python.org/3/library/collections.
	#   html?highlight=deque#collections.deque
	def __init__(self):
		self.totalsamples = 0
		self.totalperiod = 0
		return

def totals_counts_resetfn(auxdata):
	auxdata.totalsamples = 0
	auxdata.totalperiod = 0
	return

def totals_increment_counts(auxdata, sample):
	tag = 'totals_increment_counts'

	auxdata.totalsamples += 1
	auxdata.totalperiod += sample.period

	return

# sample must be a perf_sample object.
def totals_counts_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'totals_counts_datafn'

	sample = plot_event.perf_sample
	if sample is None:
		return None

	totals_increment_counts(auxdata, sample)

	point = datapoint()
	point.appname = currentapp
	point.timestamp = sample.time
	point.count = auxdata.totalperiod
	seriesname = currentapp

	return [(seriesname, point)]

##############################################################################

def totals_ts_plotfn(seriesdict, plotname, workingdir):
	tag = 'totals_ts_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict)

	# Set up y-axis splits: set to None to just use one plot, or pass
	# a list of maximum y-values and plot_time_series will split up
	# the series into multiple plots, each plot with a different y-axis.
	bil = 1000000000
	if 'dTLB-loads' in plotname:
		ysplits = [5*bil, 10*bil, 15*bil, 20*bil, 40*bil, 60*bil, 80*bil]
	elif 'dTLB-stores' in plotname:
		ysplits = [5*bil, 10*bil, 15*bil, 20*bil]
	else:
		ysplits = []

	title = ("Cumulative {} count").format(plotname)
	xaxis = "Execution time"
	yaxis = "Count"
	return plot_time_series(plotdict, title, xaxis, yaxis, ysplits,
			logscale=False, yax_units='billions', cp_series=cp_series)

def totals_col_plotfn(seriesdict, plotname, workingdir):
	tag = 'totals_col_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict, uselastpoint=True)

	title = ("Total {} count").format(plotname)
	xlabel = ''
	ylabel = 'Count'
	return plot_columns_old(plotdict, title, xlabel, ylabel, sortcolumns=True,
			logscale=False, yax_units='billions')

def new_totals_ts_plot(eventname):
	plotname = "{}-total-ts".format(eventname)
	return multiapp_plot(plotname, totals_counts_auxdata,
		totals_ts_plotfn, totals_counts_datafn,
		totals_counts_resetfn)

def new_totals_col_plot(eventname):
	plotname = "{}-total-col".format(eventname)
	return multiapp_plot(plotname, totals_counts_auxdata,
		totals_col_plotfn, totals_counts_datafn,
		totals_counts_resetfn)

if __name__ == '__main__':
	print_error_exit("not an executable module")
