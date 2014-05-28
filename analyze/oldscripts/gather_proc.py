#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from vm_regex import *
from pjh_utils import *
import vm_common as vm
import errno
import os
import re
import stat
import sys

proc_files_we_care_about = ("cmdline", "maps", "smaps", "comm", "status")

'''
output_subdir should have just been created, and should be empty.
'''
def copy_proc_files(pid_dir, output_subdir):
	tag = "copy_proc_files"

	# pid_dir is a /proc/[pid] directory, and output_subdir is a corresponding
	# [pid] subdirectory in the output directory. Scan through the list of
	# files that we care about and copy the contents of each one to the output
	# directory. Because /proc files are not normal file system files, we
	# don't use a copy command, but instead open every file for reading and
	# then write every line to the output file.

	for fname in proc_files_we_care_about:
		proc_fname = "{0}/{1}".format(pid_dir, fname)
		out_fname = "{0}/{1}".format(output_subdir, fname)
		print_debug(tag, ("copying '{0}' to '{1}'".format(
			proc_fname, out_fname)))
		vm.copy_proc_file_old(proc_fname, out_fname)

def gather_proc_files(output_dir):
	tag = "gather_proc_files"

	proc_root = "/proc"

	# Scan through all of the files under /proc, and for every process
	# subdirectory (names with just a PID), copy the files that we care
	# about to a corresponding directory in the output directory.
	if not os.path.exists(proc_root):
		print_error_exit(tag, ("proc_root directory '{0}' does not "
			"exist!").format(proc_root))
	dir_contents = os.listdir(proc_root)

	for item in dir_contents:
		match = valid_pid_dir.match(item)
		if match:
			pid = match.group(1)
			pid_dir = "{0}/{1}".format(proc_root, pid)
			if os.path.isdir(pid_dir):
				output_subdir = "{0}/{1}".format(output_dir, pid)
				os.mkdir(output_subdir)
				copy_proc_files(pid_dir, output_subdir)

	return

def create_output_dir(output_dir):
	tag = "create_output_dir"

	if os.path.exists(output_dir):
		print_error_exit(tag, "Output directory '{0}' already exists".format(
			output_dir))
	else:
		os.mkdir(output_dir)

	print(("Output will be created in directory '{0}'").format(output_dir))
	return

def check_requirements(output_dir):
	tag = "check_requirements"

	# Check for super-user permissions: try to open a /proc file that should
	# not be readable by normal users.
	kernel_fname = "/proc/kcore"
	try:
		f = open(kernel_fname, 'r')
		f.close()
	except IOError as e:
		#if (e == errno.EACCES):
		print_error_exit(tag, "must be run as root")

	if os.path.exists(output_dir):
		print_error_exit(tag, ("output directory '{0}' already exists").format(
			output_dir))
	return

def usage():
	print("usage: {0} <output-dir> <user>[:<group>]".format(sys.argv[0]))
	print("  <output-dir> will be created, its owner will be set to <user>, ")
	print("  and its group will optionally be set to <group>.")
	print("  This script must be run with root privilege (in order to read "
			"/proc)!")
	sys.exit(1)

def parse_args(argv):
	tag = "parse_args"

	if len(argv) != 3:
		usage()
	print_debug(tag, 'argv: {0}'.format(argv))

	output_dir = argv[1]
	usrgrp = argv[2]
	return (output_dir, usrgrp)

# Main:
if __name__ == "__main__":
	tag = "main"
	print_debug(tag, "entered")

	(output_dir, usrgrp) = parse_args(sys.argv)
	check_requirements(output_dir)
	create_output_dir(output_dir)

	gather_proc_files(output_dir)
	set_owner_group(output_dir, usrgrp)

	sys.exit(0)
else:
	print("Must run stand-alone")
	usage()
	sys.exit(1)

