#####! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Methods and classes for handling data created by a "perf record"
# command.
# IMPORTANT: the word "period" as used by perf, and hence used in
# this script as well, is misleading - period is not really an interval
# of time, but it is the "value" of a sample - that is, the number
# of events of a given type that occurred since the previous sample.
# So, when you read "period" in this script, you may wish to think
# of it as "value" or "count".

from util.pjh_utils import *
from analyze.simulate_segments_lib import *
from trace.run_common import *
from trace.traceinfo_class import *
import plotting.multiapp_plot_class as multiapp_plot
import plotting.plot_perf_missrate as plot_perf_missrate
import conf.PlotList as PlotList

import os
import re
import shlex
import subprocess

PTW_TITLE = 'DTLB page table walk cycles'
PAIR_EVENT_TO_STR = {
	'r108' : 'dTLB-load-misses',
	'r149' : 'dTLB-misses',
	'r408' : 'dTLB-load-walkcycles',
	'r449' : PTW_TITLE,
}

# Regular expressions: note that these may depend on the particular
# version of perf that is used to generate the perf.dump files, and
# definitely depend on the additional output messages that I added
# for raw dump files (in tools/perf/util/session.c:dump_sample()).
# Ugh, spaces in VERBOSE regexes are obnoxious.
perf_event_header_re = re.compile(r"""
	[#]\ event\ :\ name\ =\ (?P<eventname>[a-zA-Z0-9\-_]+),
	\ type\ =\ (?P<type>[\d]+),
	\ .+
	id\ =\ {\ (?P<eids>[\d, ]+)\ }
	""", re.VERBOSE)
  # Example:
  #   # event : name = dTLB-loads, type = 3, config = 0x3, config1 = 0x0,
  #   config2 = 0x0, excl_usr = 0, excl_kern = 0, excl_host = 0,
  #   excl_guest = 1, precise_ip = 0, id = { 19453, 19454 }

perf_sample_re = re.compile(r"""
	@\ id=(?P<eid>[\d]+),
	period=(?P<period>[\d]+),
	pid=(?P<pid>[\d]+),
	cpu=(?P<cpu>[\d]+),
	time=(?P<time>[\d]+)\ ,
	thread=(?P<task>[\w\-<>. \#~/:+]+),
	dso=(?P<dso>.+)$
	""", re.VERBOSE)
  # Example:
  #   @ id=19458,period=7610977,pid=20671,cpu=1,time=1271035105125778

##############################################################################

# How data is organized for this analysis:
# class perf_events_tracker keeps two mappings of the events that are
# listed in the header of the report files: one by name, and one by
# eid (event id).
#   class perf_event_info keeps track of all of the stats for a particular
#   event (e.g. dTLB-load-misses), in total and by pid.
#     class perf_event_proc_info keeps track of mostly the same stats
#     as a perf_event_info, but for just a single pid.
# As the raw perf dump is scanned, the (one and only) perf_events_tracker
# maps samples to their specific perf_event_info and tracking goes from
# there.

class perf_sample:
	tag = 'perf_sample'

	eid           = None   # use 'eid' because 'id' is reserved
	period        = None   # a.k.a. "value" or "count" - see note at top.
	pid           = None
	cpu           = None
	time          = None
	task          = None
	dso           = None
	name          = None
	is_miss_event = None
	elapsed       = None   # time since previous sample for ANY event
	appname       = None   # used for plotting/output; may differ from task

	# sample_match must be a match object from perf_sample_re. appname
	# will be used for creating plot series and possibly for other
	# output; it should likely come from the very top levels of the
	# perf_analysis script.
	def __init__(self, sample_match, appname):
		tag = "{}.__init__"

		if not sample_match:
			print_error(tag, ("invalid arg: sample_match={}").format(
				sample_match))
			return

		self.eid    = int(sample_match.group('eid'))
		self.period = int(sample_match.group('period'))
		self.pid    = int(sample_match.group('pid'))
		self.cpu    = int(sample_match.group('cpu'))
		self.time   = int(sample_match.group('time'))
		self.task   = sample_match.group('task')
		self.dso    = sample_match.group('dso')
		self.name   = None
		self.is_miss_event = None
		self.elapsed = None
		self.appname = appname

		return

	def __str__(self):
		s = ("sample: eid={}, period={}, pid={}, cpu={}, time={}, "
				"name={}, is_miss_event={}, elapsed={}").format(
				self.eid, self.period, self.pid, self.cpu, self.time,
				self.name, self.is_miss_event, self.elapsed)
		return s


class perf_event_proc_info:
	"""docstring..."""
	tag = 'perf_event_proc_info'

	pid = None
	proc_samples = None
	proc_period = None
	proc_time = None
	plotlist = None

	def __init__(self, pid):
		tag = "{}.__init__".format(self.tag)

		if pid is None:
			print_error(tag, ("invalid argument: pid={}").format(pid))
			return
		if pid is 0:
			print_warning(tag, ("pid is 0 - check when/why perf data "
				"uses this!").format())

		self.pid = pid
		self.proc_samples = 0
		self.proc_period = 0
		self.proc_time = 0
		self.plotlist = list()

		return

	def proc_handle_sample(self, sample):
		tag = "{}.proc_handle_sample".format(self.tag)

		self.proc_samples += 1
		self.proc_period += sample.period
		self.proc_time += sample.elapsed

		return

	def addplot_for_proc(self, newplot):
		self.plotlist.append(newplot)
		return

	def proc_handle_redirected_sample(self, sample, leaderpid):
		tag = "{}.proc_handle_redirected_sample".format(self.tag)

		for plot in self.plotlist:
			plot.consume_perf_sample(sample, leaderpid)

		return

class perf_event_info:
	"""docstring..."""
	tag = 'perf_event_info'

	name = None
	eids = None
	is_miss_event = None
	totalsamples = None
	totalperiod = None
	totaltime = None
	procs = None
	process_groups = None
	plotlist = None

	def __init__(self, name, eids, process_groups):
		tag = "{}.__init__".format(self.tag)

		if not name or not eids or len(eids) is 0:
			print_error(tag, ("invalid arg: name={}, eids={}").format(
				name, eids))

		self.name = name
		self.is_miss_event = is_miss_event(name)

		self.eids = list()   # new list seems like a good idea...
		for eid in eids:
			if type(eid) != int:
				print_error(tag, ("invalid eid {}, not an int!").format(
					eid))
				break
			self.eids.append(eid)
		print_debug(tag, ("created new event {} with {} eids: "
			"{}").format(self.name, len(self.eids), self.eids))

		self.totalsamples = 0
		self.totalperiod = 0
		self.totaltime = 0
		self.procs = dict()
		self.process_groups = process_groups   # ok to be none
		self.plotlist = list()

		return

	# The first thing that this method does is set a couple of fields
	# of the sample object: name and is_miss_event.
	def event_handle_sample(self, sample):
		tag = "{}.event_handle_sample".format(self.tag)

		# The caller mapped the sample to my event, so set the sample's
		# properties to match mine:
		sample.name = self.name
		sample.is_miss_event = self.is_miss_event

		# In one trace I got these consecutive events in the perf dump:
		#   @ id=67,period=308263,pid=0,cpu=0,time=2220420008347
		#   @ id=69,period=2405,pid=0,cpu=0,time=2220420008347
		# So, at the exact same nanosecond, two samples were recorded
		# for different events (dTLB-loads and dTLB-load-misses) on the
		# same cpu. Huh.
		#   Does this mean that each *core* has two hw counters? If so,
		#   then why does the perf summary report say that these events
		#   only were active for 50% of the trace when I gather four
		#   events in the same run??
		# Then to calculate the elapsed time, does this mean that we
		# should keep track of timestamps on a per-EVENT basis? No, that
		# wouldn't work, would just make it look like every event was
		# always being counted at all times.
		# Anyway, let's just not use the elapsed time / totaltime for
		# anything important right now, since it can't really be
		# trusted...
		#   TODO: see how perf tool estimates the amount of time that
		#   each event spent running on the hw counters in order to
		#   do scaling - then imitate that here.
		if sample.elapsed is None:
			sample.elapsed = 0
			print_warning(tag, ("first sample with elapsed=None: will "
				"continue with stats calculations here (so that our "
				"output will match perf report summary), but using "
				"elapsed=0 since we have no idea what the real value "
				"is. {}").format(sample))
		elif sample.elapsed is 0:
			print_warning(tag, ("sample.elapsed is {} - ugh").format(
				sample.elapsed))
			return

		# For our perf event, we want to track:
		#   The total period/count of these events.
		#   The total amount of time elapsed while these events were
		#     tracked on the hw counters.
		#   The period/count per-pid.
		#   ...
		self.totalsamples += 1
		self.totalperiod += sample.period
		self.totaltime += sample.elapsed

		procinfo = self.get_perf_proc_info(sample.pid)
		if not procinfo:
			procinfo = self.add_new_perf_proc_info(sample.pid)

		procinfo.proc_handle_sample(sample)

		#print_debug(tag, ("{}: pid {}: proc_samples={}, proc_period={}, "
		#	"proc_time={}").format(self.name, procinfo.pid,
		#	procinfo.proc_samples, procinfo.proc_period,
		#	procinfo.proc_time))
		#print_debug(tag, ("{}: totalsamples={}, totalperiod={}, "
		#	"totaltime={}").format(self.name, self.totalsamples,
		#	self.totalperiod, self.totaltime))

		# Get the leader of the group that this sample pid belongs
		# to and tell it to pass the sample to its plot methods. If
		# no leader is found, then it means that sample.pid isn't
		# found in process_groups, so we don't really care about it.
		leader_procinfo = self.get_leader_perf_proc_info(sample.pid)
		if leader_procinfo:
			#print_debug(tag, ("redirecting sample with pid {} to "
			#	"leader of process group {}").format(sample.pid,
			#	leader_procinfo.pid))
			leader_procinfo.proc_handle_redirected_sample(sample,
					leader_procinfo.pid)

		return

	def add_new_perf_proc_info(self, pid):
		tag = "{}.add_new_perf_proc_info".format(self.tag)

		procinfo = perf_event_proc_info(pid)
		self.procs[pid] = procinfo

		return procinfo

	# Returns a perf_event_proc_info, or None if not found for the
	# specified pid.
	def get_perf_proc_info(self, pid):
		tag = "{}.get_proc_info".format(self.tag)

		try:
			procinfo = self.procs[pid]
		except KeyError:
			procinfo = None

		return procinfo

	# Returns the proc_info that is the leader/head of the process group
	# that contains the specified pid. If process_groups is empty, then
	# the proc_info of the specified pid is simply returned.
	# Returns: the leader proc_info, or None if not found. If not-found
	# is returned, then it's not an error, but simply means that we don't
	# care about this pid because it's not found anywhere in process_groups.
	def get_leader_perf_proc_info(self, pid):
		tag = "{}.get_leader_perf_proc_info".format(self.tag)

		if len(self.process_groups) is 0:
			return self.get_perf_proc_info(pid)

		leaderpid = process_groups_leader(self.process_groups, pid)
		if not leaderpid:
			print_debug(tag, ("no leader found for pid {}").format(pid))
			return None

		return self.get_perf_proc_info(leaderpid)

	# Takes the multiapp_plot object and adds it to the plotlist for
	# the specific pid, which represents the top-level "leader" process
	# in a process group.
	def addplot(self, newplot, leaderpid):
		tag = "{}.addplot".format(self.tag)

		procinfo = self.get_perf_proc_info(leaderpid)
		if not procinfo:
			procinfo = self.add_new_perf_proc_info(leaderpid)
		else:
			print_warning(tag, ("at addplot time, right now we expect "
				"procinfos to not exist yet, but found one for "
				"{} - what changed?").format(leaderpid))

		procinfo.addplot_for_proc(newplot)
		print_debug(tag, ("{}: added newplot to leader procinfo {}").format(
			self.name, procinfo.pid))
	
		return

	def print_totals_by_pid(self, outputfile):
		tag = "{}.print_totals_by_pid".format(self.tag)

		outputfile.write("Event {}:\n".format(self.name))
		outputfile.write(("Totals: samples={},\tperiod={},\ttime="
			"{}\n").format(self.totalsamples, self.totalperiod,
			self.totaltime))

		for procinfo in reversed(sorted(self.procs.values(),
				key=lambda p: p.proc_period)):
			s = ("\tpid={}\tsamples={}\tperiod={}\ttime={}").format(
					procinfo.pid, procinfo.proc_samples,
					procinfo.proc_period, procinfo.proc_time)
			outputfile.write("{}\n".format(s))

		return

class perf_events_tracker:
	"""docstring..."""
	tag = 'perf_events_tracker'

	process_groups = None
	events_by_name = None
	events_by_eid = None
	total_samples = None
	cpu_sample_times = None

	def __init__(self, process_groups):
		tag = "{}.__init__".format(self.tag)

		self.process_groups = process_groups   # ok to be none
		self.events_by_name = dict()
		self.events_by_eid = dict()
		self.total_samples = 0
		self.cpu_sample_times = dict()

		return

	# eids must be a list of ints.
	def add_new_event(self, name, eids):
		tag = "{}.add_new_event".format(self.tag)

		retval = True
		perf_event = perf_event_info(name, eids, self.process_groups)

		try:
			exists = self.events_by_name[perf_event.name]
			print_error(tag, ("event {} already present! Will not "
				"overwrite").format(perf_event.name))
			retval = False
		except KeyError:
			self.events_by_name[perf_event.name] = perf_event

		for eid in perf_event.eids:
			try:
				exists = self.events_by_eid[eid]
				print_error(tag, ("event {} already present! Will "
					"not overwrite").format(eid))
				retval = False
				break
			except KeyError:
				self.events_by_eid[eid] = perf_event
				print_debug(tag, ("added perf_event to events_by_"
						"eid[{}]").format(eid))

		if retval:
			print_debug(tag, ("inserted event {} into mappings by name "
				"and by eid").format(perf_event.name))

		return retval

	# Returns the found perf_event_info, or None if not found.
	def get_by_name(self, name):
		try:
			perf_event = self.events_by_name[name]
		except KeyError:
			perf_event = None
		return perf_event

	def get_perf_events(self):
		# events_by_name should have only one mapping to each
		# perf_event_info object.
		return self.events_by_name.values()

	def get_eventnames(self):
		# events_by_name should have only one mapping to each
		# perf_event_info object.
		return self.events_by_name.keys()

	# sample is a perf_sample object.
	def handle_sample(self, sample):
		tag = "{}.handle_sample".format(self.tag)

		success = self.set_sample_elapsed(sample)
		if not success:
			return False

		retval = True
		try:
			perf_event = self.events_by_eid[sample.eid]
			perf_event.event_handle_sample(sample)
		except KeyError:
			print_error(tag, ("no event known for sample.eid={}! "
				"(type={})").format(sample.eid, type(sample.eid)))
			retval = False

		self.total_samples += 1
		self.prev_sample_time = sample.time

		return retval

	# Sets the elapsed time field of the sample by tracking the previous
	# sample timestamp seen *on each cpu*. For the first sample seen
	# on a particular cpu, we don't know the elapsed time, so
	# sample.elapsed will be set to None.
	#
	# Currently, this logic assumes that there is a single hw counter
	# running on each of verbena's cpu cores at all times - so, every
	# time we get a new sample, we can infer that the time period for
	# which that sample's events were counted is the entire time since
	# the previous sample from that cpu core.
	#   I have no idea if this is the actual architecture of the hw
	#   counters or not... what if the number of counters is greater
	#   than the number of cores? Then what does the mapping look like??
	#   Do the counters have some sort of unique identifier that I can
	#   get??
	#
	# Returns: False on error (i.e. timestamps out-of-order), True on
	# success.
	def set_sample_elapsed(self, sample):
		tag = "{}.set_sample_elapsed".format(self.tag)

		try:
			prev_sample_time = self.cpu_sample_times[sample.cpu]
			if sample.time < prev_sample_time:
				print_error(tag, ("sample.time {} is less than "
					"prev_sample_time={} for cpu {}!").format(
					sample.time, prev_sample_time, sample.cpu))
				return False

			elapsed = sample.time - prev_sample_time
		except KeyError:
			# What should we do for the first sample?! I checked the
			# perf report output and it doesn't give you a timestamp
			# for when the perf record began - so, let's not set the
			# sample's elapsed time at all, and whoever works with
			# the samples will have to handle this appropriately
			# (e.g. by skipping the first sample).
			elapsed = None

		sample.elapsed = elapsed
		self.cpu_sample_times[sample.cpu] = sample.time
		#print_debug(tag, ("set sample.elapsed={} and updated "
		#	"cpu_sample_times[{}] = {}").format(sample.elapsed,
		#	sample.cpu, self.cpu_sample_times[sample.cpu]))

		return True

	# This method can be used to compare the analysis data against
	# the summary perf report generated using the flags
	# "-n --show-total-period -s pid". I verified on 1/18/14 that
	# my initial perf analysis for a run with no child processes
	# printed totals that matched this report.
	def print_event_totals(self, outputfile):
		tag = "{}.print_event_totals".format(self.tag)

		for (name, perf_event) in self.events_by_name.items():
			perf_event.print_totals_by_pid(outputfile)
			outputfile.write('\n')

		return

##############################################################################

HAS_MISS_EVENT = {   # for perf in linux-3.9.4
		'dTLB-loads'			: 'dTLB-load-misses',
		'dTLB-stores'			: 'dTLB-store-misses',
		'dTLB-prefetches'		: 'dTLB-prefetch-misses',
		'iTLB-loads'			: 'iTLB-load-misses',
		'L1-dcache-loads'		: 'L1-dcache-load-misses',
		'L1-dcache-stores'		: 'L1-dcache-store-misses',
		'L1-dcache-prefetches'	: 'L1-dcache-prefetch-misses',
		'L1-icache-loads'		: 'L1-icache-load-misses',
		'L1-icache-prefetches'	: 'L1-icache-prefetch-misses',
		'LLC-loads'				: 'LLC-load-misses',
		'LLC-stores'			: 'LLC-store-misses',
		'LLC-prefetches'		: 'LLC-prefetch-misses',
	}
HAS_PAIR_EVENT = {
		'r108'	: 'cycles',
		'r149'	: 'cycles',
		'r408'	: 'cycles',
		'r449'	: 'cycles',
	}

def is_miss_event(eventname):
	tag = 'is_miss_event'

	# Example of miss events: dTLB-load-misses, dTLB-store-misses,
	# dTLB-prefetch-misses, iTLB-load-misses, L1-dcache-load-misses,
	# etc.
	if 'misses' in eventname:
		return True
	# Hack: for event / plotting purposes, treat TLB walk cycle events
	# as "misses", so they they'll count towards the numerator that
	# will be divided by 'cycles':
	if eventname in ['r408', 'r449']:
		print_debug(tag, ("treating event name {} as a miss event").format(
			eventname))
		return True
	return False

# Creates plots appropriate for the specified events. If both event
# and missevent are specified, then new missrate plots will be
# created; otherwise, if just event is specified, then just a
# standard perf plot will be created...
#
# When plots are created for the events, one plot will be created
# for the top-level perf_event_infos, and then these are responsible
# for creating plots specific to each perf_event_proc_info.
# 
# Returns: a list of the created plots.
def create_event_plots(perf_events, event, missevent, pairevent):
	tag = 'create_event_plots'

	newplots = []
	for group in perf_events.process_groups:
		leader = group[0]
		if type(leader) != int:
			print_error_exit(tag, ("assert failed: leader={} is "
				"not an int ({})").format(leader, type(leader)))

		if event and missevent:
			print_debug(tag, ("looking for event={} ("
				"missevent={}) in PlotList.missrate_event_plots={}").format(
				event.name, missevent.name,
				PlotList.missrate_event_plots))
			if event.name in PlotList.missrate_event_plots:
				# We want to create one new multiplot for every group of
				# processes in the process_groups. (In practice, so far
				# there is only ever just one process group, but we should
				# be able to handle more). This is slightly problematic
				# because we want to link the *same* multiplot to two
				# different events here, the normal event and the missevent.
				# This means that we have to create the plots out here,
				# external to the events, and then pass them in; this means
				# that the process group logic has to go here, and not
				# inside of the event class (where it would be slightly
				# cleaner). Oh well.

				# Make sure that plots don't have the same name, or they
				# will overwrite each other!
				pl = []
				missplot_ts = plot_perf_missrate.new_missrate_ts_plot(
						missevent.name)
				pl.append(missplot_ts)
				missplot_avg = plot_perf_missrate.new_missrate_avg_plot(
						event.name)
				pl.append(missplot_avg)

				for p in pl:
					event.addplot(p, leader)
					missevent.addplot(p, leader)
					newplots.append(p)
			else:
				print_debug(tag, ("not creating plot for "
					"event={} that's not in missrate_event_plots").format(
					event.name))

		if event and pairevent:
			print_debug(tag, ("looking for event={} ("
				"pairevent={}) in PlotList.perf_pair_plots={}").format(
				event.name, pairevent.name, PlotList.perf_pair_plots))
			if event.name in PlotList.perf_pair_plots:
				# Hack: copied this code from missrate code above, to
				# get it working quick and dirty.

				# Make sure that plots don't have the same name, or they
				# will overwrite each other!
				pl = []
				try:
					name = PAIR_EVENT_TO_STR[event.name]
				except KeyError:
					#name = "{}".format(event.name)
					name = "{}-{}".format(event.name, pairevent.name)
				pairplot_ts = plot_perf_missrate.new_rate_ts_plot(name)
				pl.append(pairplot_ts)
				pairplot_avg = plot_perf_missrate.new_rate_avg_plot(name)
				pl.append(pairplot_avg)

				for p in pl:
					event.addplot(p, leader)
					pairevent.addplot(p, leader)
					newplots.append(p)
			else:
				print_debug(tag, ("not creating plot for "
					"event={} that's not in perf_pair_plots").format(
					event.name))

		if event:  # plots for lone events:
			for (eventlist, newplotfn) in PlotList.perf_plotlist:
				print_debug(tag, ("searching for event {} in eventlist "
					"{}").format(event.name, eventlist))
				if event.name in eventlist:
					p = newplotfn(event.name)
					event.addplot(p, leader)
					newplots.append(p)

		else:
			print_error(tag, ("bad input - event is None, missevent "
				"is {}").format(missevent))

	return newplots

# outputdir should already exist.
# Returns: True on success, False on error.
def perf_gen_reports(perfdata_fname, outputdir):
	tag = 'perf_gen_reports'

	success = True

	print_debug(tag, ("opening output files in outputdir {}: "
		"{}, {}").format(outputdir, PERF_DUMPFILE, PERF_REPORTFILE))
	fdump   = open("{}/{}".format(outputdir, PERF_DUMPFILE), 'w')
	freport = open("{}/{}".format(outputdir, PERF_REPORTFILE), 'w')

	# Dump raw perf event data:
	#   -vvv for increased verbosity
	#   -I for more detailed header
	#   -D for raw data.
	# The size of the dump file may be large - a 1.4 MB perf.data file
	# becomes a 35 MB perf.dump file, e.g. ~25x larger.
	cmd = "{} report -vvv -ID -i {}".format(PERF_CMD, perfdata_fname)
	print_debug(tag, "cmd={}".format(cmd))
	args = shlex.split(cmd)
	retcode = subprocess.call(args, stdout=fdump, stderr=fdump)
	if retcode != 0:
		print_error(tag, ("perf report raw-dump command returned "
			"error={}").format(retcode))
		if retcode == 244:
			print_error_exit(tag, ("retcode {}: failed to open perf.data: "
				"Permission denied. Means that you likely forgot to "
				"turn tracing off in your app script!").format(retcode))
		success = False

	# Create summary report of perf data:
	#   -I for more detailed header
	#   -n: print a column for number of samples
	#   --show-total-period: print a column with sum of "periods,"
	#     which really means the sum of the event counts.
	#   -s: sort summary data by pid
	# This report is meant to be human rather than machine readable;
	# for easier parsing, add "-t ," to delimit with commas.
	cmd = "{} report -I -n --show-total-period -s pid -i {}".format(
			PERF_CMD, perfdata_fname)
	print_debug(tag, "cmd={}".format(cmd))
	args = shlex.split(cmd)
	retcode = subprocess.call(args, stdout=freport, stderr=freport)
	if retcode != 0:
		print_error(tag, ("perf report summary command returned "
			"error={}").format(retcode))
		success = False

	fdump.close()
	freport.close()

	return success

# appname is just for debugging.
def handle_sample_line(line, perf_events, appname):
	tag = 'handle_sample_line'

	sample_match = perf_sample_re.match(line)
	if not sample_match:
		print_error(tag, ("perf_sample_re didn't match line {}!").format(
			line))
		return

	sample = perf_sample(sample_match, appname)

	perf_events.handle_sample(sample)
	#print("SAMPLE: {}: {}".format(appname, sample))

	return

def handle_event_header(perf_events, event_header_match):
	tag = 'handle_event_header'

	if not event_header_match:
		print_error(tag, "event_header_match is None!")
		return

	event_name     = event_header_match.group('eventname').strip()
	event_eids_str = event_header_match.group('eids')
	posint_re = re.compile(r'\d+')
	event_eids = posint_re.findall(event_eids_str)
	event_eids = list(map(int, event_eids))
	print_debug(tag, ("event {}: eids={}").format(event_name, event_eids))

	success = perf_events.add_new_event(event_name, event_eids)
	if not success:
		print_error(tag, ("failed to add new event {}, will return "
			"False").format(event_name))

	return success

# Once we've seen the entire perf report header, perform the following
# steps:
#   Use the events to determine which plots to use.
#   ...?
# Returns: a list of multiapp_plot objects (which may be empty!), or
# None on error.
def header_complete(perf_events):
	tag = 'header_complete'

	allplots = []
	eventlist = perf_events.get_perf_events()
	for event in eventlist:
		# Look for pairs of events where one tracks total events and
		# the other tracks just the misses. When we encounter one
		# of these event pairs, create a new perf_missrate_plot,
		# and tell these events to pass their samples to this plot's
		# datafn.
		try:
			missname = HAS_MISS_EVENT[event.name]
			missevent = perf_events.get_by_name(missname)
			if not missevent:
				print_warn(tag, ("event {} should have a miss "
					"partner {}, but that event not found in "
					"perf_events tracker").format(event.name,
					missname))
			else:
				print_debug(tag, ("found event-miss pair: ({}, "
					"{})").format(event.name, missevent.name))
		except KeyError:
			missevent = None

		pairname = HAS_PAIR_EVENT.get(event.name)
		if pairname:
			pairevent = perf_events.get_by_name(pairname)
			if not pairevent:
				print_warn(tag, ("event {} should have a pair "
					"event {}, but the pair event is not found "
					"in the perf_events tracker").format(event.name,
					pairname))
			else:
				print_debug(tag, ("found event pair: ({}, "
					"{})").format(event.name, pairevent.name))
		else:
			pairevent = None

		newplots = create_event_plots(perf_events, event, missevent,
					pairevent)
		allplots += newplots   # don't use .append()!

	return allplots

# Returns: nothing
def setup_perf_plots(allplots, outputdir, appname, pdffile=None):
	tag = 'setup_perf_plots'

	print_debug(tag, ("setting all plots in allplots list to use "
		"{} as workingdir and appname={}").format(outputdir, appname))
	for plot in allplots:
		plot.reset()
		plot.set_workingdir(outputdir)
		plot.set_currentapp(appname)
		plot.add_pdffile(pdffile)

	return

# Analyzes the perf.dump file generated by perf_gen_reports() and
# creates data files for plotting.
# Returns: a list of multiapp_plot objects that were created during the
# raw dump analysis.
def perf_analyze_rawdump(outputdir, process_groups, appname):
	tag = 'perf_analyze_rawdump'

	fname = "{}/{}".format(outputdir, PERF_DUMPFILE)
	if not fname:
		print_error(tag, ("no perf dump file found at {}").format(
			fname))
		return False
	dumpfile = open(fname, 'r')

	perf_events = perf_events_tracker(process_groups)

	allplots = []
	headerstate = None
	linenum = 0
	line = None
	while True:
		linenum += 1
		line = dumpfile.readline()
		if not line:
			break
		print_debug("dumpfile line", "{}".format(linenum))

		# Figure out what type of message/event this line is:
		#   'sample': a sample event that matches the particular line
		#     format that I added to perf raw dump output.
		#   'event_header': line that describes an event found in the perf
		#     data file.
		#   'header_begin_end': line delineating the beginning or end
		#     of the header at the top of the raw dump.
		#   'dontcare'
		linetype = 'dontcare'
		if line[0] == '@':
			linetype = 'sample'
		elif line[0] == '#':
			event_header_match = perf_event_header_re.match(line)
			if event_header_match:
				linetype = 'event_header'
			elif re.match('^# ========', line):
				linetype = 'header_begin_end'

		# How are multi-app plots handled for perf analysis? Well, right
		# now we only ever care to analyze one app at a time - that
		# app may involve one process (pid) or many, but in process_groups
		# there should only be one top-level group.
		# So where should the plots be managed? In the first analysis
		# phase, all of the plots are constructed up-front, and then
		# every vma is passed to every one of them, and it's up to the
		# datafn to weed out the vmas it doesn't care about. In this
		# perf analysis script we take a slightly different approach:
		# instead of a single group of plots, we "assign" a smaller
		# number of plots to each event, so that the plot datafns should
		# tend to only receive samples that they care about. Within
		# the event objects (perf_event_info) we handle the process
		# grouping: one multiplot object will be created for every
		# top-level process in the process_groups, and samples for
		# the other sub-processes in the group will be directed to the
		# one top-level process for that group.

		# Switch on line type and pass the line to various handler
		# methods:
		success = True
		if linetype == 'sample':
			handle_sample_line(line, perf_events, appname)
		elif linetype == 'event_header':
			success = handle_event_header(perf_events, event_header_match)
		elif linetype == 'header_begin_end':
			if headerstate == None:
				headerstate = 'begin'
			elif headerstate == 'begin':
				headerstate = 'ended'
				allplots += header_complete(perf_events)
				setup_perf_plots(allplots, outputdir, appname)
		elif linetype == 'dontcare':
			pass
		else:
			print_error(tag, "invalid linetype {}".format(linetype))
			break

		if not success:
			print_error(tag, ("handler for linetype {} failed, breaking "
				"out of loop now").format(linetype))
			break

	dumpfile.close()

	perf_events.print_event_totals(sys.stdout)

	return allplots

# Returns: a list of plots that were dynamically created according to
# the events in the perf reports.
def perf_analyze_reports(outputdir, group_multiproc, target_pids,
		appname, process_groups):
	tag = 'perf_analyze_reports'

	allplots = perf_analyze_rawdump(outputdir, process_groups, appname)

	return allplots

# Analyzes perf.data files using "perf report" and creates data files
# to be used for plots. perfdata_fname is the path+name of the perf.data
# file (output by run_apps.py). outputdir will be created if it does not
# exist yet to store the output files in. appdir should contain any
# files generated by previous analysis phases that we want to leverage
# here (namely the process_groups).
# Some of these arguments are ignored: process_userstacks, lookup_fns.
#
# Returns: a list of multiapp_plots that were created during analysis.
def perf_main(perfdata_fname, appdir, group_multiproc,
		process_userstacks, lookup_fns, target_pids, appname,
		skip_page_events):
	tag = 'perf_main'

	# Attempt to read the process_groups from the appdir, where the
	# previous analysis phase has hopefully written them. For perf
	# analysis we only care about the pids, not the task names...
	process_groups = read_process_groups(appdir, include_task=False,
			include_pid=True)
	if not process_groups or len(process_groups) is 0:
		print_warning(tag, ("couldn't read in process_groups from "
			"appdir {}, processes will not be grouped").format(appdir))
		process_groups = None
	else:
		print_debug(tag, ("process_groups (pids only): {}").format(
			process_groups))
		if len(process_groups) > 1:
			print_warning(tag, ("process_groups has {} top-level "
				"groups! Beware, this script has only really been "
				"tested with a single process group.").format(
				len(process_groups)))

	outputdir = "{}/{}".format(appdir, PERFREPORT_DIRNAME)
	if not os.path.exists(outputdir):
		os.makedirs(outputdir)
	else:
		print_warning(tag, ("outputdir {} already exists, will "
			"overwrite files in it!").format(outputdir))

	# First, run perf report commands on the perf.data files and store
	# the report output in new files.
	success = perf_gen_reports(perfdata_fname, outputdir)
	if not success:
		print_debug(tag, "perf_gen_reports failed, returning now")
		return

	# Second, analyze the raw perf report data and generate plot data.
	allplots = perf_analyze_reports(outputdir, group_multiproc,
			target_pids, appname, process_groups)

	# Finally, save the plot data for this perf analysis run. Should only
	# be called once per invocation of this script.
	multiapp_plot.serialize_plotlist_data(allplots)

	return allplots

# Main:
if __name__ == '__main__':
	tag = 'main'

	print("Not a standalone script yet!")
	sys.exit(1)

	sys.exit(0)
