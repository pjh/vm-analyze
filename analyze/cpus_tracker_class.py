# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
from trace.vm_common import *
from analyze.cpu_information_class import *

# ...
class cpus_tracker:
	"""docstring..."""
	tag = "class cpus_tracker"

	# Members:
	cpu_dict = None
	max_cpus = None
	
	# max_cpus: optional argument for max number of cpus expected.
	def __init__(self, max_cpus=None):
		tag = "{0}.__init__".format(self.tag)

		self.reset(max_cpus)
		return
	
	def reset(self, max_cpus=None):
		tag = "{0}.reset".format(self.tag)

		self.cpu_dict = dict()
		self.max_cpus = max_cpus
		return

	# Returns the cpu_info object for the specified cpu.
	# Returns None if the cpu is not found.
	def get_cpu_info(self, cpu):
		tag = "{0}.get_cpu_info".format(self.tag)

		try:
			cpu_info = self.cpu_dict[cpu]
		except KeyError:
			return None

		#if cpu_info.get_cpu() != cpu:
		#	print_error_exit(tag, ("got cpu_info {0} from cpu_dict, "
		#		"but its cpu doesn't match lookup cpu {1}").format(
		#		cpu_info.to_str(), cpu))

		return cpu_info

	# Returns the new cpu_information object; aborts on error.
	def add_new_cpu(self, cpu):
		tag = "{0}.add_new_cpu".format(self.tag)

		try:
			cpu_info = self.cpu_dict[cpu]
			print_error_exit(tag, ("got already-existing "
				"cpu_info for cpu {0}!").format(cpu))
			return None
		except KeyError:
			cpu_info = cpu_information()
			self.cpu_dict[cpu] = cpu_info
		return cpu_info

	# Returns a list of all of the cpu_info objects that are being
	# tracked, sorted by ascending cpu.
	def get_all_cpu_infos(self):
		tag = "get_all_cpu_infos"

		return list(map(lambda x:x[1],
			sorted(self.cpu_dict.items(), key=lambda x:x[0])))

	def num_cpus_seen(self):
		return len(self.cpu_dict)

if __name__ == '__main__':
	print_error_exit("not an executable module")
