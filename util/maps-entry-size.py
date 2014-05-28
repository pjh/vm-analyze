#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from trace.vm_regex import *
from util.pjh_utils import *
from trace.vm_common import *
import sys

def usage():
	print(("usage: {0} <maps-entry-line>").format(sys.argv[0]))
	print(("  maps-entry-line: comes from a /proc/pid/maps file"))
	sys.exit(1)

# Main:
if __name__ == '__main__':
	tag = "main"

	argv = sys.argv
	if len(argv) < 2:
		usage()
	
	hex_range = argv[1]
	match = hex_range_line.match(hex_range)

	if match:
		begin = int(match.group("begin"), 16)
		end = int(match.group("end"), 16)
		#print_debug("", "begin={0}, end={1}".format(
		#	hex(begin), hex(end)))
		diff = end - begin
		pages = diff / 4096
		pretty = pretty_bytes(diff)
		print(("Range [{0}, {1}]:").format(hex(begin), hex(end-1)))
		print(("\t{0} bytes\t{1} pages\t{2}").format(diff, pages, pretty))
	else:
		print(("first arg {0} didn't match hex range as expected").format(
			hex_range))
	
	sys.exit(0)
else:
	print("Must run stand-alone")
	usage()
	sys.exit(1)
