# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

'''
Class used for passing events from analysis script to multiapp_plot
objects.
'''
class PlotEvent:
	tag = 'PlotEvent'

	# All of these members are optional - typically, only one or maybe
	# two will be set to non-None.
	vma = None            # class vm_mapping
	page_event = None     # class PageEvent
	cp_event = None       # class CheckpointEvent
	perf_sample = None    # class perf_sample
	datapoint = None      # arbitrary (understood by a particular datafn)

	def __init__(self, vma=None, page_event=None, cp_event=None,
			perf_sample = None, datapoint=None):
		tag = "{}.__init__".format(self.tag)

		self.vma = vma
		self.page_event = page_event
		self.cp_event = cp_event
		self.perf_sample = perf_sample
		self.datapoint = datapoint

		return

if __name__ == '__main__':
	print_error_exit("not an executable module")

