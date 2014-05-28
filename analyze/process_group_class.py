# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *

'''
TODO: move process_group stuff from analyze_trace.py and simulate_segments_lib
into this file/class!
'''
#class process_group:
#	tag = 'process_group'
#
#	...

# Iterates over all of the process_infos in the group, gets their vmas
# from the specified table, and concatenates them all together in a list
# which is returned.
# whichtable should be one of: 'vmatable', 'cp_vmas', or 'all_vmas'.
# The caller can sort the returned list using something like:
#   sorted_vmalist = sorted(vmalist, key=lambda vma: vma.xyz)
def get_group_vmalist(proc_group, whichtable):
	tag = 'get_group_vmalist'

	vmalist = []
	for proc in proc_group:
		# Use + and += for list concatenation:
		#   >>> X = [1]
		#   >>> Y = [2, 3]
		#   >>> X += Y
		#   >>> print(X)
		#   [1, 2, 3]
		#print_debug(tag, ("getting unsorted vmalist for {}'s {}").format(
		#	proc.name(), whichtable))
		proclist = proc.get_vmalist(whichtable, sort=False)
		vmalist += proclist
		#print_debug(tag, ("{}: added {} vmas to vmalist").format(
		#	proc.name(), len(proclist)))

	#print_debug(tag, ("returning vmalist with {} total vmas").format(
	#	len(vmalist)))
	return vmalist

if __name__ == '__main__':
	print_error_exit("not an executable module")
