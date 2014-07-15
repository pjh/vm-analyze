# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.plot_components_ops import components_ops_plot
from plotting.plot_components_vmas import components_vmas_plot
from plotting.plot_vmacount import vmacount_ts_plot, vmacount_max_col_plot
from plotting.plot_vmaops import *
from plotting.plot_addrspace_sizes import vm_size_ts_plot, resident_ts_plot, resident_table, virt_phys_size_ts_plot, virt_phys_ratio_ts_plot, virt_phys_size_component_ts_plot, virt_phys_ratio_component_ts_plot, virt_pte_size_ts_plot, virt_pte_ratio_ts_plot, virt_phys_diff_ts_plot
#from plotting.plot_perf_missrate import *
from plotting.plot_perf_totals import new_totals_ts_plot, new_totals_col_plot
from util.pjh_utils import *

# note: this plotlist is searched linearly... make sure it
#   doesn't get *too* big.
point_in_time_plotlist = [
		'vaspace_plots',
		'os_overheads_plot',
		'basepagesize_plot',
		'max_vmas_plot',
		#'vma_categories_plot',
		'vma_size_cols_plot',
		'vma_size_cdf_plot',
		'vma_size_portion_plot',
	]
# For each point_in_time plot, plot it at each of these times:
points_in_time = [
		#'max_vma_count',
		'max_vm_size',   # prefer this one
	]

# analysis_plotlist: list of multiapp_plot_class objects
#   "ts" means "time-series"
analysis_plotlist = [
		# Pure vma plots:
		vmacount_ts_plot,
		vmacount_max_col_plot,
		#vmaops_all_plot,
		#vmaops_allocs_plot,
		#vmaops_frees_plot,
		vmaops_resizes_plot,
		#vmaops_relocations_plot,
		vmaops_access_changes_plot,
		#vmaops_flag_changes_plot,
		#vmaops_nonallocfree_plot,
		vm_size_ts_plot,

		# Rss plots:
		resident_table,
		resident_ts_plot,
		virt_phys_size_ts_plot,
		virt_phys_ratio_ts_plot,
		virt_phys_diff_ts_plot,
		
		# PTE plots:
		#virt_pte_size_ts_plot,
		#virt_pte_ratio_ts_plot,
		#virt_phys_size_component_ts_plot,  # causing chrome + kbuild errors??
		#virt_phys_ratio_component_ts_plot, # causing chrome + kbuild errors??

		# Old plots:
		###components_ops_plot,   # old
		###components_vmas_plot,   # old
	]

# Plots to make for perf analysis: if events are encountered in the perf
# dump that match events in these lists, then a plot with the type
# described by the list will be created for that event.
# perf_plotlist contains tuples that map the list of events to the method
# used to create the new plot - the new plot method should only take
# the event name as an argument, and return a multiapp_plot object.
missrate_event_plots = [
		#'dTLB-loads',
		#'dTLB-stores',
		#'iTLB-loads',
	]
totals_ts_plots = [
		##'dTLB-loads',
		##'dTLB-stores',
		##'iTLB-loads',
	]
totals_col_plots = [
		##'dTLB-loads',
		##'dTLB-stores',
		##'iTLB-loads',
	]
perf_plotlist = []  # list of tuples: (eventlist, method to create new plot)
perf_plotlist.append((totals_ts_plots, new_totals_ts_plot))
perf_plotlist.append((totals_col_plots, new_totals_col_plot))

def analysis_plotlist_str():
	s = ""
	for plot in analysis_plotlist:
		s += " {}".format(plot.plotname)
	return s

if __name__ == '__main__':
	print_error_exit("not an executable module")
