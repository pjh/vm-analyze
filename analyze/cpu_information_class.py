# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
from trace.vm_common import *

# ...
class cpu_information:
	"""docstring..."""
	tag = "class cpu_information"

	# Members:
	current_pid = None
	
	def __init__(self):
		tag = "{0}.__init__".format(self.tag)

		self.reset()
		return
	
	def reset(self):
		tag = "{0}.reset".format(self.tag)

		current_pid = None
		return

	# Will return None if no pid has ever been set.
	def get_current_pid(self):
		return self.current_pid

	# Returns the previous pid (which may be None if never set).
	def set_current_pid(self, newpid):
		oldpid = self.current_pid
		self.current_pid = newpid
		return oldpid

if __name__ == '__main__':
	print_error_exit("not an executable module")
