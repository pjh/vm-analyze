#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from analyze.argparsers import sum_vm_parser
from util.pjh_utils import *
from trace.vm_common import *
from trace.vm_regex import *

# Globals:

##############################################################################

class MapsFileStats:
	tag = 'MapsFileStats'

	def __init__(self):
		tag = "{}.__init__".format(self.tag)

		self.stats = dict()
		self.is_bytes = dict()
		self.maxkeylen = 0

		return

	# Adds a numeric value to the specified key:
	def add_to_stats(self, key, value, is_bytes=False):
		tag = "{}.add_to_stats".format(self.tag)

		try:
			self.stats[key] += value
		except KeyError:
			self.stats[key] = value
		#print_debug(tag, ("stats[{}] = {}").format(key, self.stats[key]))

		if is_bytes:
			self.is_bytes[key] = True

		if len(key) > self.maxkeylen:
			self.maxkeylen = len(key)

		return

	def print_stats(self):
		tag = "{}.print_stats".format(self.tag)

		for (key, value) in self.stats.items():
			keystr = key.rjust(self.maxkeylen + 2)
			try:
				is_bytes = self.is_bytes[key]
				valstr = pretty_bytes(value)
			except KeyError:
				valstr = str(value)
			print(("{}: {}").format(keystr, valstr))

		return

##############################################################################
# Returns: an open file handle, or None on error.
def open_maps_file(maps_fname):
	tag = 'open_maps_file'

	try:
		maps_f = open(maps_fname, 'r')
	except IOError:
		print_error(tag, ("couldn't open {} for reading").format(
			maps_fname))
		return None

	return maps_f

# Iterates over the lines in the maps file and adds up the size of all of
# the vmas.
# Returns: nothing.
def process_mapsfile(maps_f):
	tag = 'process_mapsfile'

	mapstats = MapsFileStats()
	linenum = 0

	while True:
		linenum += 1
		line = maps_f.readline()
		if not line:
			break

		maps_match = maps_line_re.match(line)
		if not maps_match:
			print_debug(tag, ("not a maps line: {}").format(line))
			continue

		# regex values:
		begin_addr = int(maps_match.group('begin_addr'), 16)
		end_addr = int(maps_match.group('end_addr'), 16)
		perms = maps_match.group('perms').strip()
		offset = int(maps_match.group('offset'), 16)
		dev_major = int(maps_match.group('dev_major'), 16)
		dev_minor = int(maps_match.group('dev_minor'), 16)
		inode = int(maps_match.group('inode'))
		filename = maps_match.group('filename').strip()

		# constructed values:
		length = end_addr - begin_addr
		perms_key = construct_perms_key(perms, inode, filename)

		mapstats.add_to_stats('vma-count', 1)
		mapstats.add_to_stats('total-vm-size', length, True)

		if 'f' in perms_key:
			mapstats.add_to_stats('vma-count-file', 1)
			mapstats.add_to_stats('total-vm-size-file', length, True)
		else:
			mapstats.add_to_stats('vma-count-anon', 1)
			mapstats.add_to_stats('total-vm-size-anon', length, True)

	mapstats.print_stats()

	return

def handle_args(argv):
	tag = 'handle_args'

	parser = sum_vm_parser
	args = parser.parse_args(argv)
	#print_debug(tag, ("parser returned args={}").format(args))

	if args.maps_fname is None or len(args.maps_fname) < 2:
		print_error(tag, ("invalid maps_fname {}").format(maps_fname))
		return (None)

	return (args.maps_fname)

##############################################################################
# Main:
if __name__ == '__main__':
	tag = 'main'

	(maps_fname) = handle_args(sys.argv[1:])
	if not maps_fname:
		print_error(tag, "exiting")
		sys.exit(1)

	maps_f = open_maps_file(maps_fname)
	if not maps_f:
		print_error(tag, "exiting")
		sys.exit(1)

	process_mapsfile(maps_f)

	maps_f.close()

	sys.exit(0)
else:
	print('Must run stand-alone')
	sys.exit(1)
