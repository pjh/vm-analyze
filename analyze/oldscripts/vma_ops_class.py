# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from pjh_utils import *

'''
'''
class vma_ops_tracker:
	tag = "class vma_ops_tracker"

	# Members:
	allocs = None
	frees = None
	resizes = None
	relocations = None
	access_changes = None
	flag_changes = None

	def __init__(self):
		tag = "{0}.__init__".format(self.tag)

		self.reset()
		return

	def reset(self):
		self.allocs = 0
		self.frees = 0
		self.resizes = 0
		self.relocations = 0
		self.access_changes = 0
		self.flag_changes = 0
		return

	def inc_vma_op(self, vma_op):
		tag = "{0}.inc_vma_op".format(self.tag)

		if   vma_op == 'alloc':          self.allocs += 1
		elif vma_op == 'free':           self.frees += 1
		elif vma_op == 'resize':         self.resizes += 1
		elif vma_op == 'relocation':     self.relocations += 1
		elif vma_op == 'access_change':  self.access_changes += 1
		elif vma_op == 'flag_change':    self.flag_changes += 1
		else:
			print_error_exit(tag, ("invalid vma_op: {0}").format(
				vma_op))
		return
	
	def count_ops(self):
		return (self.allocs + self.frees + self.resizes + self.relocations +
			self.access_changes + self.flag_changes)
	
	def count_ops_care_about(self):
		# We don't care about relocations (because they wouldn't involve
		# physical memory manipulation of segments) and flag changes
		# (because flags are internal to the OS).
		#   Actually, we don't really care about access_changes either...
		#return (self.allocs + self.frees + self.resizes + self.access_changes)
		return (self.allocs + self.resizes + self.access_changes)

	'''
	def inc_allocs(self):
		self.allocs += 1
		return

	def inc_frees(self):
		self.frees += 1
		return

	def inc_resizes(self):
		self.resizes += 1
		return

	def inc_relocations(self):
		self.relocations += 1
		return

	def inc_access_changes(self):
		self.access_changes += 1
		return

	def inc_flag_changes(self):
		self.flag_changes += 1
		return
	'''

