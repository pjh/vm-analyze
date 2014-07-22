# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.plot_components_ops import components_ops_plot
from plotting.plot_components_vmas import components_vmas_plot
from plotting.plot_vmacount import vmacount_ts_plot, vmacount_max_col_plot
from plotting.plot_vmaops import *
from plotting.plot_addrspace_sizes import vm_size_ts_plot, resident_ts_plot, resident_table, virt_phys_size_ts_plot, virt_phys_ratio_ts_plot, virt_phys_size_component_ts_plot, virt_phys_ratio_component_ts_plot, virt_pte_size_ts_plot, virt_pte_ratio_ts_plot, virt_phys_diff_ts_plot
from plotting.plot_perf_totals import new_totals_ts_plot, new_totals_col_plot
from util.pjh_utils import *

# note: this plotlist is searched linearly... make sure it
#   doesn't get *too* big.
point_in_time_plotlist = [
		'os_overheads_plot',		# used in paper
		'basepagesize_plot',		# used in paper
		'max_vmas_plot',			# used in paper
		'vma_categories_plot',		# used in paper
		'vma_size_cdf_plot',		# used in paper
		'vma_size_portion_plot',	# used in paper
		#'vaspace_plots',			# only used for one app in paper
		##'vma_size_cols_plot',		# not used in paper
	]
# For each point_in_time plot, plot it at each of these times:
points_in_time = [
		'max_vma_count',
		'max_vm_size',   # prefer this one
	]

# analysis_plotlist: list of multiapp_plot_class objects
#   "ts" means "time-series"
analysis_plotlist = [
		# Pure vma plots:
		vmacount_ts_plot,
		vm_size_ts_plot,
		vmaops_resizes_plot,
		vmaops_access_changes_plot,
		##vmaops_all_plot,			# not used in paper
		##vmaops_allocs_plot,		# not used in paper
		##vmaops_frees_plot,		# not used in paper
		##vmaops_relocations_plot,	# not used in paper
		##vmaops_flag_changes_plot,	# not used in paper
		##vmaops_nonallocfree_plot,	# not used in paper
		##vmacount_max_col_plot,	# not used in paper, old way

		# Rss plots:
		resident_table,				# used in paper
		#resident_ts_plot,			# not used in paper
		#virt_phys_size_ts_plot,	# not used in paper
		#virt_phys_ratio_ts_plot,	# not used in paper
		#virt_phys_diff_ts_plot,	# not used in paper
		
		# PTE plots: OLD
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
perf_pair_plots = [
		'r408',			# DTLB_LOAD_MISSES.WALK_CYCLES: not used in paper?
		'r449',			# DTLB_MISSES.WALK_CYCLES: used in paper
	]
missrate_event_plots = [
		#'dTLB-loads',	# not used in paper
		#'dTLB-stores',	# not used in paper
		#'iTLB-loads',
	]
totals_ts_plots = [
		##'dTLB-loads',
		##'dTLB-stores',
		##'iTLB-loads',
		##'r408',
		##'r449',
	]
totals_col_plots = [
		##'dTLB-loads',
		##'dTLB-stores',
		##'iTLB-loads',
		##'r408',
		##'r449',
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
