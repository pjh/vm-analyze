# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

import trace.vm_common as vm

'''
Describes trace events that caused the rss page count (resident in physical
memory) to change.
'''
class RssEvent:
	tag = "RssEvent"

	rss_pages = None
	timestamp = None

	# rss_dict is a mapping from RSS_TYPES to page counts. After
	# initialization, the RssEvent.rss_pages mapping is guaranteed to
	# have an entry for each type in RSS_TYPES.
	def __init__(self, rss_dict, timestamp):
		tag = "{0}.__init__".format(self.tag)

		if not rss_dict or not timestamp:
			print_error_exit(tag, ("invalid arg: rss_dict={}, timestamp="
				"{}").format(rss_dict, timestamp))

		self.rss_pages = dict()
		for rss_type in vm.RSS_TYPES:
			# todo: make RSS_TYPES an enum, and just use a list here
			# instead of creating yet another dict.
			if rss_type in rss_dict:
				self.rss_pages[rss_type] = rss_dict[rss_type]
			else:
				self.rss_pages[rss_type] = 0
		self.timestamp = timestamp
		return

if __name__ == '__main__':
	print_error_exit("not an executable module")

