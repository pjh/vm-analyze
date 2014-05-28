# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from trace.run_common import *
from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.plots_common import *
from trace.vm_mapping_class import *

##############################################################################

class components_ops_auxdata:
	components = None
	def __init__(self):
		self.components = dict()

def components_ops_resetfn(auxdata):
	auxdata.components = dict()
	return

def components_ops_datafn(auxdata, plot_event, tgid, currentapp):
	tag = 'components_ops_datafn'

	vma = plot_event.vma
	if vma is None:
		return None

	# Skip over the dup-mmap and exit-mmap operations that occur when a
	# typical process forks + execs, for now; they just product unsightly
	# spikes in the plots.
	#events_to_skip = []
	events_to_skip = ['dup_mmap', 'exit_mmap']
	for skip in events_to_skip:
		if skip in vma.kernel_fn:
			print_debug(tag, ("found '{}' in vma's kernel_fn, so "
				"ignoring this vma").format(skip))
			return None

	points = []
	total = 'Total'
	component = determine_component_plot(vma)

	for comp in [component, total]:
		try:
			comp_count = auxdata.components[comp]
		except KeyError:
			comp_count = 0

		if not vma.is_unmapped:
			comp_count += 1
			point = datapoint()
			point.appname = currentapp
			point.timestamp = vma.timestamp
			point.count = comp_count
		else:
			# Ignore unmap events - just counting total operations
			continue
			#comp_count -= 1
			#point = (vma.unmap_timestamp, comp_count)

		#print_debug(tag, ("point type: ({}, {})").format(
		#	type(point[0]), type(point[1])))

		if comp_count < 0:
			print_error_exit(tag, ("count for {} hit {}; unmap "
				"timestamp is {}, vma is {}").format(comp, comp_count,
				vma.unmap_timestamp, vma.to_str_maps_format()))
		auxdata.components[comp] = comp_count

		'''
		if multiapp_right_now:
			name = "{}-{}".format(currentapp, comp)
		else:
			name = "{}".format(comp)
		'''
		name = "{}-{}".format(currentapp, comp)
		#name = "{}".format(comp)
		points.append((name, point))

	return points

def components_ops_plotfn(seriesdict, plotname, workingdir):
	tag = 'components_ops_plotfn'

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict)

	ysplits = None
	title = ("Virtual memory operations performed by component").format()
	xaxis = "Execution time"
	yaxis = "Count of virtual memory operations"

	return plot_time_series(plotdict, title, xaxis, yaxis, ysplits,
			logscale=False, cp_series=cp_series)

components_ops_plot = multiapp_plot('Components-Ops', components_ops_auxdata,
		components_ops_plotfn, components_ops_datafn, components_ops_resetfn)

if __name__ == '__main__':
	print_error_exit("not an executable module")
