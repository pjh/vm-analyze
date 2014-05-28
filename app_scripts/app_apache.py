# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

# Build + setup instructions: do these once / occasionally by hand, not
# done automatically by this script.
#   ...

from app_scripts.app_to_run_class import app_to_run
import trace.ubuntu_services

USE_MANUAL_CLIENT = True

##############################################################################

def apache_exec(outputdir):
	tag = 'apache_exec'
	
	if USE_MANUAL_CLIENT:
		return ubuntu_services.runservice_manualclient(outputdir, 'apache2')
	else:
		print_error(tag, ("automated client not set up yet").format())
	return None

# First arg is "appname" member: used to construct output directory.
apache_app = app_to_run('apache', apache_exec)

if __name__ == '__main__':
	print_error_exit("not an executable module")
