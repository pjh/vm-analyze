# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

'''
Contains information about events involving PTEs; used for plotting.
'''
class PageEvent:
	tag = "PageEvent"

	pte = None     # class PTE
	timestamp = None
	unmap = None

	# pte is a PTE object. unmap indicates whether this page event is
	# mapping or unmapping the specified pte.
	def __init__(self, pte, timestamp, unmap=False):
		tag = "{0}.__init__".format(self.tag)

		if not pte or not timestamp:
			print_error_exit(tag, ("invalid arg: pte={}, timestamp="
				"{}, unmap={}").format(pte, timestamp, unmap))

		self.pte = pte
		self.timestamp = timestamp
		self.unmap = unmap

		return

if __name__ == '__main__':
	print_error_exit("not an executable module")

