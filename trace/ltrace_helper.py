# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

LTRACE_ON = True

LTRACE_FNAME = 'ltrace.out'

if LTRACE_ON:
	import conf.system_conf as sysconf
	LTRACE_OUTFILE = "{}/{}".format(sysconf.LTRACE_DIR, LTRACE_FNAME)
	LTRACE_CMD = "ltrace -c -C -f -o {}".format(LTRACE_OUTFILE)

	# Make sure ltrace output directory exists
	import os
	try:
		os.mkdir(sysconf.LTRACE_DIR)
	except FileExistsError:
		pass

	LTRACE_ENV = ("VMSTUDY_LTRACE=\"ltrace -c -C -f -o {}\"").format(
			LTRACE_OUTFILE)

else:
	LTRACE_CMD = ' '
	LTRACE_OUTFILE = None
	LTRACE_ENV = ''

# TOOD: add a helper file here that copies the LTRACE_OUTFILE to
# a specified destination directory, and changes its group + owner
# to non-root!

##############################################################################

if __name__ == '__main__':
	print("Cannot run stand-alone")
	sys.exit(1)
