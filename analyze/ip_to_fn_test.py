#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *  #this is going to fail if not in top-level dir...
from ip_to_fn import *

# Main:
if __name__ == '__main__':
	tag = 'main'

	# The way to use this test file is to first do a test application run
	# (i.e. of hello-world) with userstacktraces active. Then, look at
	# the maps files from the run to see where the r-xpf vmas for
	# hello-world and libc started in the address space, and fill in
	# the hw_addr and libc_addr below. Then, look at an actual stacktrace
	# that's printed (see example below) and fill in the test 'addr'
	# values below, and check that the output of this script matches
	# what you see when you run "objdump -d " on hello-world and libc.
	helloworld = '/home/pjh/research/virtual/apps/test-programs/hello-world'
	hw_addr = int('0x00400000', 16)
	#libc = '/lib/x86_64-linux-gnu/libc-2.15.so'
	libc = '/home/pjh/research/virtual/glibc-testinstall/lib/libc-2.17.so'
	libc_addr = int('0x7fdfb405d000', 16)

	ip_to_fn = ip_to_fn_converter()

	'''
	# An actual userstacktrace: line 2337 in
	# measurement_results/20130918-11.28.18/manual-app-1/trace-events-full
	hello-world-6948  [001] .... 74981.051938: <user stack trace>
	[001] =>  <00007fdfb41472fa>
	[001] =>  <00007fdfb40d722c>
	[001] =>  <00007fdfb40d6688>
	[001] =>  <00007fdfb40d5815>
	[001] =>  <00007fdfb40a427f>
	[001] =>  <00007fdfb40aee08>
	[001] =>  <000000000040081c>
	[001] =>  <00000000004008f5>
	[001] =>  <00007fdfb407e995>
	[001] =>  <00000000004006d9>

	libc-2.17.so start-addr: 0x7fdfb405d000
	hello-world start-addr: 0x000000400000

	Expected output (bottom of stack towards top):
	lookup 0x4006d9 in helloworld: _start
	lookup 0x7fdfb407e995 in libc: __libc_start_main
	lookup 0x4008f5 in helloworld: main
	lookup 0x40081c in helloworld: procedure
	lookup 0x7fdfb40aee08 in libc: __printf
	...
	Makes sense, woooooooo!
	'''

	addr = int('00000000004006d9', 16)
	fn = ip_to_fn.lookup(helloworld, addr, hw_addr)
	print("lookup {} in helloworld: {}".format(hex(addr), fn))

	addr = int('00007fdfb407e995', 16)
	fn = ip_to_fn.lookup(libc, addr, libc_addr)
	print("lookup {} in libc: {}".format(hex(addr), fn))

	addr = int('00000000004008f5', 16)
	fn = ip_to_fn.lookup(helloworld, addr, hw_addr)
	print("lookup {} in helloworld: {}".format(hex(addr), fn))

	addr = int('000000000040081c', 16)
	fn = ip_to_fn.lookup(helloworld, addr, hw_addr)
	print("lookup {} in helloworld: {}".format(hex(addr), fn))

	addr = int('00007fdfb40aee08', 16)
	fn = ip_to_fn.lookup(libc, addr, libc_addr)
	print("lookup {} in libc: {}".format(hex(addr), fn))

	ip_to_fn.close()

	sys.exit(0)
else:
	print('Must run stand-alone')
	usage()
	sys.exit(1)
