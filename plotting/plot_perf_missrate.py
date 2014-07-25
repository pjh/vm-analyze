# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.plots_common import *
import analyze.perf_analysis
import collections

##############################################################################

# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Constant values are ok.

WINDOWSIZE = 9.5 * 100000000
  # I added careful elapsed-time calculation around the perf commands
  # in traceinfo, and took the difference of the first + last sample
  # timestamps to determine the approximate number of perf "ticks"
  # in 1 second: 
  #   (1458721287519172 - 1458668384014328) /  54.12233677599579 = 977480057
  #   (1459390482068310 - 1459317588013134) /  75.01912375492975 = 971672975
  #   (1460030876589345 - 1459890052013885) / 156.37578079989180 = 900552340
  # Ok, I don't know how 900 million relates to my CPU clock speed or any
  # other clock, but I'll use, say, 950 million as the WINDOWSIZE for
  # one-second intervals.
  # In my initial tests, a windowsize of 200 million or 400 million
  # led to lots of up-spikes at various spots throughout the execution
  # of most of the apps - seems like it would be best to avoid these
  # spikes...

class missrate_ts_auxdata:
	tag = 'missrate_ts_auxdata'

	# Python simple queues: http://docs.python.org/3/library/collections.
	#   html?highlight=deque#collections.deque
	def __init__(self):
		self.samplequeue = collections.deque()
		self.windowtotal = 0
		self.windowmisses = 0
		self.prev_missrate = 0.0
		self.totalsamples = 0
		self.firstsampletime = -1
		print_debug(self.tag, ("missrate timeseries plots: using WINDOWSIZE="
			"{}").format(WINDOWSIZE))
		return

def missrate_ts_resetfn(auxdata):
	auxdata.samplequeue.clear()
	auxdata.windowtotal = 0
	auxdata.windowmisses = 0
	auxdata.prev_missrate = 0.0
	auxdata.totalsamples = 0
	auxdata.firstsampletime = -1
	return

# Adds the sample to the queue of samples in auxdata that is used
# to keep track of a "sliding window" of samples.
# Returns: the miss rate for the current window.
def missrate_update_window(auxdata, sample):
	tag = 'missrate_update_window'

	minwindow = sample.time - WINDOWSIZE

	while (len(auxdata.samplequeue) > 0 and
			auxdata.samplequeue[0].time < minwindow):
		# window is inclusive (not that it actually matters...)
		removed = auxdata.samplequeue.popleft()
		#print_debug(tag, ("removed sample with time {} from window "
		#	"[{}, {}]").format(removed.time, minwindow, sample.time))
		
		if removed.is_miss_event:
			auxdata.windowmisses -= removed.period
			if auxdata.windowmisses < 0:
				# I think that this should never happen unless the window
				# size is made crazy small - with a reasonable window
				# size we should always have at least one other sample
				# left in the queue to give windowmisses / windowtotal a
				# positive value...
				print_unexpected(True, tag, ("windowmisses {} fell below "
					"0?! Make sure that this makes sense.").format(
					auxdata.windowmisses))
		else:
			auxdata.windowtotal -= removed.period
			if auxdata.windowtotal < 0:
				print_unexpected(True, tag, ("windowtotal {} fell below "
					"0?! Make sure that this makes sense.").format(
					auxdata.windowtotal))
	
	auxdata.samplequeue.append(sample)
	if sample.is_miss_event:
		auxdata.windowmisses += sample.period
	else:
		auxdata.windowtotal += sample.period
	#print_debug(tag, ("added sample with time {} to end of "
	#	"window").format(sample.time))

	# Adjust the missrate to handle unusual / incorrect cases. We keep
	# track of the missrate *used* (not necessarily the missrate that
	# was calculated) for the previous sample, and if anything looks
	# wrong, we just keep using the previous sample, so that any
	# problematic cases at least don't jump out like crazy in the
	# plot...
	WINDOWS_TO_WAIT = 1
	if sample.time < (auxdata.firstsampletime +
			          WINDOWSIZE * WINDOWS_TO_WAIT):
		# Avoid huge spikes in miss rate at beginning of execution
		# that occur when some number of miss samples are received
		# first - when the first non-miss sample is then received,
		# its period is way less than the sum of the initial miss
		# samples, causing the big spike in miss rate. This has
		# occurred in multiple apps.
		#   The choice of WINDOWS_TO_WAIT is arbitrary - just keep
		#   increasing it if/when you see the spikes in the plots,
		#   I guess. Note that decreasing the WINDOWSIZE (which is
		#   also set arbitrarily right now...) will impact this
		#   as well.
		# Great: for Graph500, with a WINDOWS_TO_WAIT of just 1,
		# the large spikes are all filtered out by this case, and
		# none of the other unusual cases below are hit at all!
		# (for both -F 1000 and -F 100, and when tracking just TLB
		#  loads and both TLB loads+stores with -F 1000).
		#print_debug(tag, ("skipping sample with time {}, which is "
		#	"within the first {} windows of the trace").format(
		#	sample.time, WINDOWS_TO_WAIT))
		missrate = auxdata.prev_missrate
	elif auxdata.windowtotal != 0:
		if auxdata.windowmisses > auxdata.windowtotal:
			# Hopefully all of these cases are filtered out by the
			# WINDOWS_TO_WAIT case above. This test alone is not
			# sufficient, because spikes up to, say, 80% miss rate
			# were still seen at the beginning of the trace.
			print_error(tag, ("windowmisses {} greater than windowtotal "
				"{}, would result in an impossible miss rate above "
				"100% - will use prev_missrate").format(
				auxdata.windowmisses, auxdata.windowtotal))
			missrate = auxdata.prev_missrate
		else:
			# this is the "normal" case.
			missrate = float(auxdata.windowmisses / auxdata.windowtotal)
	else:  # don't divide by 0:
		if auxdata.windowmisses == 0:
			missrate = 0.0
			print_error_exit(tag, ("both windowmisses and windowtotal "
				"are 0 - what the...?").format())
		else:
			# This can happen easily at the beginning of application 
			# execution, but should be filtered out by WINDOWS_TO_WAIT.
			# It's more worrisome if it happens later: could mean that
			# we're not sampling frequently enough, or that window is
			# too small.
			print_error(tag, ("auxdata.windowtotal is 0, but windowmisses "
				"is {} - we only have miss samples in the window at the "
				"moment. Increase sampling frequency or window "
				"size??").format(auxdata.windowmisses))
			missrate = auxdata.prev_missrate

	#print_debug(tag, ("auxdata: {} / {} = MISSRATE {}").format(
	#	auxdata.windowmisses, auxdata.windowtotal, missrate))
	auxdata.prev_missrate = missrate

	return missrate

##############################################################################

class missrate_counts_auxdata:
	tag = 'missrate_counts_auxdata'

	def __init__(self):
		self.totalperiod = 0
		self.missperiod = 0
		self.totalsamples = 0
		self.firstsampletime = -1
		return

def missrate_counts_resetfn(auxdata):
	auxdata.totalperiod = 0
	auxdata.missperiod = 0
	auxdata.totalsamples = 0
	auxdata.firstsampletime = -1
	return

def missrate_increment_counts(auxdata, sample):
	tag = 'missrate_increment_counts'

	auxdata.totalsamples += 1
	if auxdata.totalsamples == 1:
		auxdata.firstsampletime = sample.time

	if sample.is_miss_event:
		auxdata.missperiod += sample.period
	else:
		auxdata.totalperiod += sample.period

	return

##############################################################################

# sample must be a perf_sample object.
# This plot will create a timeseries where each point is the miss rate
# when calculated over the previous samples that occured during the
# specified WINDOWSIZE.
def missrate_window_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'missrate_window_datafn'

	sample = plot_event.perf_sample
	if sample is None:
		return None

	auxdata.totalsamples += 1
	if auxdata.totalsamples == 1:
		auxdata.firstsampletime = sample.time

	missrate = missrate_update_window(auxdata, sample)

	point = datapoint()
	point.appname = currentapp
	point.timestamp = sample.time
	point.count = missrate
	seriesname = currentapp

	return [(seriesname, point)]

# sample must be a perf_sample object.
def missrate_counts_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'missrate_counts_datafn'

	sample = plot_event.perf_sample
	if sample is None:
		return None

	missrate_increment_counts(auxdata, sample)

	# Every point is the average miss rate *so far*; the column
	# plot will just take the last point.
	point = datapoint()
	point.appname = currentapp
	point.timestamp = sample.time
	if auxdata.totalperiod != 0:
		# This may happen if initial sample(s) in perf.dump is for a
		# miss event.
		point.count = float(auxdata.missperiod / auxdata.totalperiod)
	else:
		point.count = 0
	seriesname = currentapp

	return [(seriesname, point)]

##############################################################################

def rate_ts_plotfn(seriesdict, plotname, workingdir):
	# ugh - need to separate plotname and title in multiapp_plot class...
	if analyze.perf_analysis.PTW_TITLE in plotname:
		name = analyze.perf_analysis.PTW_TITLE
		ylabel = 'Percentage of execution time'
		ysplits = [0.01, 0.05, 0.10, 0.20]
	else:
		name = plotname
		ylabel = None
		ysplits = None
	return missrate_ts_plotfn(seriesdict, name, workingdir, ylabel, ysplits)

def rate_avg_plotfn(seriesdict, plotname, workingdir):
	# ugh - need to separate plotname and title in multiapp_plot class...
	if analyze.perf_analysis.PTW_TITLE in plotname:
		name = analyze.perf_analysis.PTW_TITLE
		ylabel = 'Percentage of execution time'
	else:
		name = plotname
		ylabel = None
	return missrate_avg_plotfn(seriesdict, name, workingdir, ylabel)

def missrate_ts_plotfn(seriesdict, plotname, workingdir, ylabel=None,
		ysplits=None):
	tag = 'missrate_ts_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict)

	# Set up y-axis splits: set to None to just use one plot, or pass
	# a list of maximum y-values and plot_time_series will split up
	# the series into multiple plots, each plot with a different y-axis.
	# Need to differentiate between loads and stores here - this is kind
	# of a hack, but these numbers need to be hardcoded and re-hardcoded
	# periodically anyway, so ysplits is already a hack no matter what.
	if not ysplits:
		if 'dTLB-load-misses' in plotname:
			ysplits = [0.015, 0.04, 0.07, 0.1, 0.2, 0.3]
			  # These work well with 950mil windowsize for loads
		elif 'dTLB-store-misses' in plotname:
			#ysplits = [0.015, 0.020, 0.025]
			ysplits = [0.005, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07,
					0.08, 0.09]
		else:
			#ysplits = []
			ysplits = [0.005, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07,
					0.08, 0.09]

	title = ("{}").format(plotname)
	#title = ("{} miss rate").format(plotname)
	xaxis = "Execution time"
	if not ylabel:
		ylabel = "Miss rate"
	return plot_time_series(plotdict, title, xaxis, ylabel, ysplits,
			logscale=False, yax_units='percents', cp_series=cp_series)

def missrate_avg_plotfn(seriesdict, plotname, workingdir, ylabel=None):
	tag = 'missrate_avg_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict, uselastpoint=True)

	title = ("{}").format(plotname)
	#title = ("{} miss rate").format(plotname)
	xlabel = ''
	if not ylabel:
		ylabel = 'Average miss rate'
	return plot_columns_old(plotdict, title, xlabel, ylabel, sortcolumns=True,
			logscale=False, yax_units='percents')

# Make sure that plots don't have the same name, or they will overwrite
# each other!
def new_missrate_ts_plot(eventname):
	plotname = "{}-ts".format(eventname)
	return multiapp_plot(plotname, missrate_ts_auxdata,
		missrate_ts_plotfn, missrate_window_datafn,
		missrate_ts_resetfn)

def new_missrate_avg_plot(eventname):
	plotname = "{}-avg".format(eventname)
	return multiapp_plot(plotname, missrate_counts_auxdata,
		missrate_avg_plotfn, missrate_counts_datafn,
		missrate_counts_resetfn)

def new_rate_ts_plot(eventname):
	plotname = "{}-ts".format(eventname)
	return multiapp_plot(plotname, missrate_ts_auxdata,
		rate_ts_plotfn, missrate_window_datafn,
		missrate_ts_resetfn)

def new_rate_avg_plot(eventname):
	plotname = "{}-avg".format(eventname)
	return multiapp_plot(plotname, missrate_counts_auxdata,
		rate_avg_plotfn, missrate_counts_datafn,
		missrate_counts_resetfn)

if __name__ == '__main__':
	print_error_exit("not an executable module")
