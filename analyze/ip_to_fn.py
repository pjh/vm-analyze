# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# This file contains methods that implement a wrapper around the
# binutils "addr2line" utility, which can be used to look up instruction
# pointer values in executable files and shared object files to find
# the function (and sometimes the source code file + line number) that
# contains the ip.
# Note that each instance of "addr2line -e /path/to/binary..." will load
# that entire binary into memory while it runs; this is annoying for
# enormous binaries like firefox's libxul.so.

from util.pjh_utils import *
from analyze.vm_mapping_class import UNKNOWN_FN
import fcntl
import os
import shlex
import subprocess
import sys
import time

cache_addr2line_lookups = True
  # With caching disabled, less memory will be consumed, but it will take
  # 14 minutes to analyze the function lookups of a firefox trace. With
  # caching enabled, the analysis only takes 2 minutes.
addr2line_prog = '/usr/bin/addr2line'
file_prog = '/usr/bin/file'
linux_code_startaddr = int("0x400000", 16)
  # On x86_64 Linux anyway, all non-relocatable executables are loaded
  # into virtual address space at this address, I believe.

# Given the filename of an executable file or a shared object file,
# determines if the file is relocatable. All shared object files should
# be relocatable, and most executable files are non-relocatable, but it
# is possible to build "position independent executables" (see the "-fpic"
# and "-pie" flags in gcc(1)).
#
# This method is intended to be used when determining function names
# from instruction pointers using addr2line: if the file is relocatable,
# then an absolute ip should have the address of the file's memory mapping
# subtracted from it before passing it to addr2line. If the file is not
# relocatable, then the absolute ip can be passed directly to addr2line.
# Note that this method must create a child subprocess to check the file,
# so try not to call it too often.
#
# Returns: True/False if object file is relocatable or not, or None if an
# error occurred.
def is_objfile_relocatable(name):
	tag = 'is_objfile_relocatable'
	global file_prog
	
	# Command line that I think makes sense:
	#   file -e apptype -e ascii -e encoding -e tokens -e cdf -e elf -e tar
	#     -bn <filename>
	# This should return one of the following strings, indicating that the
	# file is relocatable or not:
	#   ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)
	#   ELF 64-bit LSB executable, x86-64, version 1 (SYSV)
	# (even position-independent executables will be described as "shared
	# object").
	filecmd = ("{} -e apptype -e ascii -e encoding -e tokens -e cdf "
		"-e elf -e tar -bn {}").format(file_prog, name)
	  # don't use -p flag, so that output will *always* have two lines
	fileargs = shlex.split(filecmd)
	print_debug(tag, ("fileargs: {}").format(fileargs))

	p = subprocess.Popen(fileargs, stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT)
	if not p:
		print_error(tag, "Popen failed for command {}".format(filecmd))
		return None

	# communicate() will wait for the process to terminate and will
	# read its output. A "timeout" arg was added for Python 3.3, but
	# verbena is only running 3.2.3 right now, so hope that the process
	# will always terminate.
	(out, err) = p.communicate()
	#retcode = p.poll()   # unnecessary, I think
	#retcode = p.wait()   # unnecessary, I think
	retcode = p.returncode
	if retcode is None:
		print_error(tag, ("unexpected: got a None retcode - subprocess "
			"has not terminated yet?!").format())
		return None
	elif retcode != 0:
		print_error(tag, ("file command returned a non-zero error code: "
			"{}").format(retcode))
		return None

	if out:
		# Convert from bytes back to string:
		out = out.decode('utf-8').strip()
	else:
		print_error(tag, "got no output from file subprocess")
		return None
	if err:
		err = err.decode('utf-8').strip()
	else:
		err = ''
	print_debug(tag, ("call to file subprocess succeeded, got stdout "
		"{} and stderr {}").format(out, err))

	# It's probably not necessary to define the expected output strings
	# so strictly here, but this will cause an error if we ever e.g.
	# move to a different architecture, at which point we can double-
	# check this code to make sure it makes sense for non-x86-64.
	#   Ah, I already found one thing that's not consistent: some files
	#   are "version 1 (SYSV)", others are "version 1 (GNU/Linux)".
	reloc_str = 'ELF 64-bit LSB shared object, x86-64, version 1'
	nonreloc_str = 'ELF 64-bit LSB executable, x86-64, version 1'
	if reloc_str in out:
		print_debug(tag, ("relocatable: {}").format(reloc_str))
		return True
	elif nonreloc_str in out:
		print_debug(tag, ("nonrelocatable: {}").format(nonreloc_str))
		return False

	print_error(tag, ("unexpected output \"{}\", doesn't match "
		"expected output from file command").format(out))
	print_error(tag, ("output: {}").format(repr(out)))
	print_error(tag, ("reloc_str: {}").format(repr(reloc_str)))
	print_error(tag, ("nonreloc_str: {}").format(repr(nonreloc_str)))
	return None

##############################################################################

# Creates an addr2line instance (subprocess) for a particular code module
# (executable file or shared object file).
# This class probably shouldn't be used directly; use the ip_to_fn_converter
# class below instead.
class addr2line_module:
	tag = 'addr2line_module'

	# Members:
	objname = None
	relocatable = None
	a2l = None    # Popen class instance representing an addr2line subprocess
	cache = None

	def __init__(self, objname):
		tag = "{}.__init__".format(self.tag)

		if not objname:
			print_error_exit(tag, "must provide an object name")
		
		self.objname = objname
		self.tag = "addr2line_module-{}".format(objname)
		self.relocatable = is_objfile_relocatable(objname)
		if self.relocatable is None:
			#print_error_exit(tag, ("is_objfile_relocatable() returned "
			#	"error, not sure how to handle gracefully inside of "
			#	"this constructor so aborting.").format())
			print_error(tag, ("is_objfile_relocatable() returned "
				"error, not sure how to handle gracefully inside of "
				"this constructor so aborting...").format())
			return None
		elif self.relocatable is True:
			print_debug(tag, ("determined that object file {} is "
				"relocatable, will subtract vma_start_addr from ips "
				"passed to this addr2line_module").format(objname))
		else:
			print_debug(tag, ("determined that object file {} is "
				"not relocatable, will use absolute ips that are passed "
				"to this addr2line_module").format(objname))

		ret = self.start_addr2line()
		if ret != 0:
			print_error_exit(tag, ("failed to start addr2line "
				"subprocess").format())

		self.cache = dict()

		return

	# Returns: the fn corresponding to this ip if it is found in the
	# cache map, or None if not found.
	def cache_lookup(self, ip):
		tag = "{}.cache_lookup".format(self.tag)
		try:
			fn = self.cache[ip]
		except KeyError:
			return None
		return fn

	# Inserts the specified ip, fn pair into the addr2line "cache" for
	# this module.
	# "Cache" isn't quite the right term, as nothing is ever evicted;
	# it's just a dictionary...
	def cache_insert(self, ip, fn):
		tag = "{}.cache_insert".format(self.tag)
		try:
			fn = self.cache[ip]
			print_error_exit(tag, ("unexpected: already a cache entry "
				"for ip {} -> {}").format(hex(ip), fn))
		except KeyError:
			self.cache[ip] = fn
			print_debug(tag, ("cache insert {} -> {}").format(hex(ip), fn))
		return

	# Passes the specified ip to addr2line and returns the function that
	# it corresponds to, if found.
	# ip should be a base-10 integer!
	# Returns: the function name if addr2line was able to lookup the ip
	#   successfully, or '' if addr2line was unsuccessful. Returns None
	#   on error.
	def ip_to_fn(self, ip, vma_start_addr):
		tag = "{}.ip_to_fn".format(self.tag)
		global linux_code_startaddr
		global cache_addr2line_lookups

		if not self.a2l:
			print_debug(tag, ("self.a2l is None, addr2line subprocess "
				"is already terminated (or was never started)").format())
			return None
		if type(ip) != int:
			print_error(tag, ("ip argument {} is not an int").format(ip))
			return None
		if vma_start_addr is None or type(vma_start_addr) != int:
			print_error(tag, ("invalid vma_start_addr: {}").format(
				vma_start_addr))
			return None

		# For relocatable object files, we must subtract the vma start
		# addr (the address where the file was mapped into the process'
		# address space) from the ip, which is assumed to be an absolute
		# ip from an execution's userstacktrace. For non-relocatable
		# executables, we directly use the absolute ip.
		if self.relocatable:
			#print_debug(tag, ("file {} is relocatable, so subtracting "
			#	"vma_start_addr {} from absolute ip {} to get ip for "
			#	"addr2line function lookup: {}").format(self.objname,
			#	hex(vma_start_addr), hex(ip), hex(ip - vma_start_addr)))
			if vma_start_addr > ip:
				print_error_exit(tag, ("unexpected: vma_start_addr {} "
					"> ip {}").format(hex(vma_start_addr), hex(ip)))
			ip -= vma_start_addr
		else:
			#print_debug(tag, ("file {} is not relocatable, so directly "
			#	"using absolute ip {} and ignoring vma_start_addr "
			#	"{}").format(self.objname, hex(ip), hex(vma_start_addr)))
			if vma_start_addr != linux_code_startaddr:
				print_error_exit(tag, ("file is non-relocatable, but "
					"its start addr {} doesn't match expected value for "
					"64-bit Linux, {} - is this expected?").format(
					hex(vma_start_addr), hex(linux_code_startaddr)))

		# See if we've already looked up this ip for this module.
		# Important: this must come after the ip is offset for relocatable
		# modules; ip must not change between now and when it is inserted
		# into the cache below.
		if cache_addr2line_lookups:
			cache_lookup_ip = ip   # for sanity checking
			fn = self.cache_lookup(ip)
			if fn:
				print_debug(tag, ("cache hit: ip {} -> fn '{}'").format(
					hex(ip), fn))
			else:
				print_debug(tag, ("cache miss: ip {}").format(hex(ip)))

		# Communicate with addr2line process if cache lookups are disabled
		# or the cache lookup just missed.
		if not cache_addr2line_lookups or fn is None:
			# Stupidly, it appears that Python's subprocess module can't
			# be used to communicate multiple times with an interactive
			# subprocess.
			#   http://docs.python.org/3/library/subprocess.html#subprocess.Popen.communicate
			#   http://stackoverflow.com/questions/3065060/communicate-multiple-times-with-a-process-without-breaking-the-pipe
			#   http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python
			#   http://stackoverflow.com/questions/11457931/running-an-interactive-command-from-within-python
			# It appears that the subprocess' stdin and stdout can just be
			# written and read directly instead. It appears that the input
			# string written to stdin must be converted to bytes first, and
			# then any output read from stdout must be converted from a byte
			# string back to a standard str as well.
			#print_debug(tag, ("addr2line: lookup ip {} in object file "
			#	"{}").format(hex(ip), self.objname))
			ip_input = """{}""".format(hex(ip))
			  # send Enter keypress: to enter in vim insert mode, hit
			  # Ctrl-v first
			self.a2l.stdin.write(bytearray(ip_input, 'utf-8'))
			#print_debug(tag, "a2l.stdin.write returned")

			# Read the output from addr2line:
			# http://docs.python.org/3/tutorial/inputoutput.html#methods-of-file-objects
			#   If self.a2l.stdout.readline() is used to read lines of output
			#     here, then after reading all of the lines, the next call to
			#     readline() will block forever. A possible workaround is to
			#     always just call readline() exactly twice, since that's what
			#     we expect addr2line's output to be, but this seems fragile.
			#   Instead, can we just call read(), which will read "the entire
			#     contents of the file"? This will block as well, since there
			#     is no EOF at the end of the output. According to some stack
			#     overflow answer for providing non-blocking reads in Python,
			#     we may be able to use the fcntl module to mark file
			#     descriptors as non-blocking.
			#       http://stackoverflow.com/a/1810703/1230197
			#     This seems to work a little better, although now the problem
			#     is that after writing to stdin, the python script here will
			#     likely attempt to read stdout before addr2line has had a
			#     chance to write to it. The problem is that we want to block
			#     <a little bit>, but not forever...
			#   Fragile but working solution: keep reading until two newlines
			#     have been encountered, or until the process has terminated.
			#     As far as I can tell addr2line will always return two lines
			#     of output when started with the "-Cif" flags, even if
			#     gibberish input is provided.
			#       $ addr2line -e test-programs/hello-world -Cif
			#       1234
			#       ??
			#       ??:0
			#       0x4006d9
			#       _start
			#       ??:0
			fd = self.a2l.stdout.fileno()
			flags = fcntl.fcntl(fd, fcntl.F_GETFL)
			fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

			output = ""
			linecount = 0
			loopcount = 0
			while linecount < 2:
				# In practice, it looks like this loop may run one or more
				# times (e.g. 41 times) without reading anything from
				# self.a2l.stdout, but then when there is data available
				# for reading, it is all available at once (both lines that
				# we expect).
				bytestr = self.a2l.stdout.read()
				if bytestr and len(bytestr) > 0:
					buf = bytestr.decode('utf-8')
					output += buf
					linecount = len(output.splitlines())
				if False:
					# When this code is enabled and stderr is set to
					# subprocess.PIPE when self.a2l if Popen'd, it
					# didn't seem to help - stderr.read() here never
					# ever returns.
					bytestrerr = self.a2l.stderr.read()
					if bytestrerr and len(bytestrerr) > 0:
						buf = bytestrerr.decode('utf-8')
						output += buf
						linecount = len(output.splitlines())
						print_error_exit(tag, ("stderr.read(): output={}, "
							"linecount={}").format(output, linecount))
				print_error_exit(tag, ("BUMMER: this code was broken for "
					"some reason after upgrading from Ubuntu 12.04 to 13.04 "
					"(or something else broke it, but I'm not sure what); "
					"perhaps due to python3 upgrade, or maybe a change to "
					"addr2line. In the loop below, the stdout.read() never "
					"actually returns anything, and we will just loop "
					"here forever.").format())
				loopcount += 1
				if loopcount % 50000 == 0:
					# Lookup time appears to depend on the size of the object
					# file, which makes sense I guess; for a test lookup in
					# my version of libc, I saw loopcount up to 10,000.
					#print_debug(tag, ("loopcount is {}, checking if "
					#	"addr2line is still alive").format(loopcount))
					self.a2l.poll()
					if self.a2l.returncode:
						print_error(tag, ("addr2line subprocess has "
							"terminated with retcode {}, returning error "
							"from this fn").format(self.a2l.returncode))
						return None
					else:
						print_debug(tag, ("addr2line subprocess is still "
							"alive, will keep looping; output buffer so far "
							"is {}").format(output))
						pass
			lines = output.splitlines()

			# Ok, now, if addr2line was able to lookup the function name, it
			# should be found in the first line of output; if not, then it
			# should have printed "??".
			fn = lines[0].strip()

			if cache_addr2line_lookups:
				if ip != cache_lookup_ip:
					print_error_exit(tag, ("cache_insert ip {} doesn't match "
						"cache_lookup_ip {}").format(hex(ip),
						hex(cache_lookup_ip)))
				self.cache_insert(ip, fn)

		# This needs to happen for both the cache hit case and the
		# just-looked-it-up case.
		if '?' in fn:
			#print_debug(tag, ("got unknown fn '{}' returned from addr2line, "
			#	"will return empty string from this fn").format(fn))
			fn = ''
		else:
			#print_debug(tag, ("got fn '{}' from addr2line output {}").format(
			#	fn, output.replace('\n', '')))
			pass

		return fn

	# The user should try to remember to call this function explicitly
	# when done using the instance of the class, but if the user forgets,
	# then the destructor (__del__) should eventually perform the same
	# cleanup operations (i.e. terminating the addr2line process).
	def close(self):
		tag = "{}.close".format(self.tag)

		self.stop_addr2line()
		self.objname = None
		self.relocatable = None
		self.cache = None
		return

	# "private" method:
	# Starts an instance of the addr2line program for converting ips into
	# function names. Returns: 0 on success, -1 on error.
	def start_addr2line(self):
		tag = "{}.start_addr2line".format(self.tag)
		global addr2line_prog

		a2lcmd = ("{} -e {} -Cif").format(addr2line_prog, self.objname)
		  # don't use -p flag, so that output will *always* have two lines
		a2largs = shlex.split(a2lcmd)
		print_debug(tag, ("a2largs: {}").format(a2largs))

		self.a2l = subprocess.Popen(a2largs, stdin=subprocess.PIPE,
				stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
				#stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		if not self.a2l:
			print_error(tag, "Popen failed for command {}".format(a2lcmd))
			return -1
		retcode = self.a2l.poll()
		if retcode:
			print_error(tag, ("addr2line subprocess already "
				"terminated, this is unexpected").format())
			retcode = self.a2l.wait()
			self.a2l = None
			return -1
		print_debug(tag, ("started addr2line subprocess with pid "
			"{}").format(self.a2l.pid))

		return 0

	# "private" method:
	def stop_addr2line(self):
		tag = "{}.stop_addr2line".format(self.tag)

		if not self.a2l:
			print_debug(tag, ("self.a2l is None, addr2line subprocess "
				"is already terminated (or was never started)").format())
			return

		# http://docs.python.org/3/library/subprocess.html#subprocess.Popen.communicate
		print_debug(tag, ("sending Ctrl-d to addr2line subprocess {} to "
			"terminate it").format(self.a2l.pid))
		stop_input = ''
		  # Ctrl-d: hit Ctrl-v first in vim insert mode to 'type' this
		  # special key
		#(out, err) = self.a2l.communicate(input=stop_input)
		(out, err) = self.a2l.communicate(
				input=bytearray(stop_input, 'utf-8'))
		  # does stop_input need to be converted to bytes?? Docs appear to
		  # say so, but code examples don't...
		if self.a2l.returncode is None:
			print_error_exit(tag, ("communicate() returned, but returncode "
				"is not set yet!").format())
		elif self.a2l.returncode != 0:
			print_warning(tag, ("terminated addr2line subprocess returned "
				"error code {}").format(self.a2l.returncode))
		else:
			print_debug(tag, ("addr2line subprocess terminated "
				"successfully").format())

		self.a2l = None
		return

	def __del__(self):
		tag = "{}.__del__".format(self.tag)

		if self.a2l:
			self.stop_addr2line()
		return

##############################################################################

# Converts instruction pointers to function names.
# Uses one addr2line_module object per file that we perform lookups in.
class ip_to_fn_converter:
	tag = 'ip_to_fn_converter'

	# Members:
	a2lmap = None

	def __init__(self):
		tag = "{}.__init__".format(self.tag)

		self.a2lmap = dict()
		return

	# Attempts to lookup the specified instruction pointer in the specified
	# file (executable file or shared object file). vma_start_addr should
	# be the address (as an int) where the file was mapped into the address
	# space when the ip was captured. If this address is unknown, then
	# setting it to 0 will likely still work for non-relocatable executable
	# files, but the lookup will likely fail (or worse, succeed incorrectly)
	# for relocatable object files or position-independent executables.
	# Returns: function name on success, empty string '' if the lookup
	#   failed, or None if there was an error.
	def lookup(self, objname, ip, vma_start_addr):
		tag = "{}.lookup".format(self.tag)

		if (not objname or not ip or type(objname) != str or type(ip) != int
				or len(objname) == 0 or vma_start_addr is None or
				type(vma_start_addr) != int):
			print_error(tag, ("invalid argument: objname {} must be a "
				"non-empty string, ip {} must be an int, vma_start_addr "
				"must be an int").format(objname, ip, vma_start_addr))
			return None

		# We keep one addr2line_module object per file:
		try:
			a2l = self.a2lmap[objname]
			print_debug(tag, ("got an existing addr2line instance for "
				"objname {}").format(objname))
		except KeyError:
			print_debug(tag, ("creating a new addr2line instance for "
				"objname {}").format(objname))
			a2l = addr2line_module(objname)
			if not a2l:
				print_error(tag, ("addr2line_module constructor "
					"failed, just returning {}").format(UNKNOWN_FN))
				return UNKNOWN_FN
			self.a2lmap[objname] = a2l

		return a2l.ip_to_fn(ip, vma_start_addr)

	def close(self):
		tag = "{}.close".format(self.tag)

		for a2l in self.a2lmap.values():
			a2l.close()
		self.a2lmap = None
		return

	def __del__(self):
		tag = "{}.__del__".format(self.tag)

		if self.a2lmap:
			self.close()
		return

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)
