# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

'''
'''
class file_iter:
	tag = "class file_iter"

	# Members:
	f = None
	key_fn = None
	write_fn = None
	complete_fn = None
	offset = -1
	reached_end = None
	next_line = None

	def __init__(self, f, key_fn, write_fn, complete_fn):
		tag = "{0}.__init__".format(self.tag)

		if not f or not key_fn or not write_fn or not complete_fn:
			print_error_exit(tag, ("null arg: f={0}, key_fn={1}, "
				"write_fn={2}, complete_fn={3}").format(
				f, key_fn, write_fn, complete_fn))

		self.f = f
		self.key_fn = key_fn
		self.write_fn = write_fn
		self.complete_fn = complete_fn
		self.offset = 1   # line number
		self.reached_end = False
		self.next_line = None

		return

	# This is expected to be "private"!
	# This method advances to the next line in the file ONLY IF
	# self.next_line is not already set - otherwise, the next_line
	# must be "consumed", i.e. by get_next_line(). This method also does
	# not change the file offset.
	# Returns True if line was advanced and self.next_line was set; returns
	# False if self.reached_end was already set, or if we just advanced
	# past the last line of the file.
	def advance_line(self):
		tag = "{0}.advance_line".format(self.tag)

		if self.reached_end:
			return False

		if not self.next_line:
			self.next_line = self.f.readline()
			if not self.next_line:
				self.reached_end = True
				self.offset = -1
				return False

		return True

	# Returns the next line from the file, or None if eof reached. The
	# file offset will be shifted to the next line.
	def get_next_line(self):
		tag = "{0}.get_next_line".format(self.tag)

		if self.reached_end:
			return None

		if not self.next_line:
			print_error_exit(tag, ("self.next_line not already set - "
				"is this ever expected?").format())
			line_left = self.advance_line()
			if not line_left:
				return None

		# To the external caller, self.offset always equals the number of
		# the line that will be returned by the next call to get_next_line().
		# So, we only advance the offset when we return a line...
		line = self.next_line
		self.offset += 1
		self.next_line = None
		self.advance_line()
		  # self.next_line must be None first, or no effect!

		return line

	# Returns the key from the next line in the file, without shifting
	# the file offset. Returns None if eof reached.
	def get_next_key(self):
		tag = "{0}.get_next_key".format(self.tag)

		line_left = self.advance_line()
		if not line_left:
			return None

		return self.key_fn(self.next_line)

	def reached_end(self):
		return self.reached_end

	def write_line(self, output_f, line):
		self.write_fn(output_f, line)
		return

	def complete(self, output_f):
		self.complete_fn(output_f)
		return

'''
"Static methods" for file_iter objects are below...
'''

