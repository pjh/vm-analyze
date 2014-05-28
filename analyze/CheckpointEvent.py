# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

'''
Class used for tracking checkpoint events in kernel trace.
'''
class CheckpointEvent:
	tag = "CheckpointEvent"

	timestamp = None
	appname = None
	cp_name = None

	# timestamp is mandatory; name is optional.
	def __init__(self, timestamp, appname, cp_name=None):
		tag = "{0}.__init__".format(self.tag)

		if not timestamp:
			print_error_exit(tag, ("timestamp must be set"))
		self.timestamp = timestamp
		self.appname = appname
		self.cp_name = cp_name

		return

if __name__ == '__main__':
	print_error_exit("not an executable module")

