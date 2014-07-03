# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from util.pjh_utils import *
from app_scripts.app_to_run_class import *

#test_manual = True
test_manual = False

# run_applist: list of app_to_run objects
if not test_manual:
	from app_scripts.app_cassandra import cassandra_app
	from app_scripts.app_dedup import dedup_app
	from app_scripts.app_browser import firefox_app, chrome_app
	from app_scripts.app_graph500 import g500_omp_app, g500_seq_app
	from app_scripts.app_helloworld import helloworld_app, helloworld_static_app
	from app_scripts.app_kernelbuild import kernelbuild_app
	from app_scripts.app_LAMP import LAMP_apache_app, LAMP_memcached_app, LAMP_mysql_app
	from app_scripts.app_memcached import memcached_app
	from app_scripts.app_office import office_app
	from app_scripts.app_python import python_app
	run_applist = [
		LAMP_apache_app,
		cassandra_app,
		chrome_app,
		dedup_app,
		firefox_app,
		g500_omp_app,
		helloworld_app,
		memcached_app,
		LAMP_mysql_app,
		office_app,
		python_app,
		###helloworld_static_app,
		###LAMP_memcached_app,
		###kernelbuild_app,
	]
else:
	from app_scripts.app_manual import *
	from app_scripts.app_LAMP import LAMP_apache_manual_app, LAMP_mysql_manual_app
	run_applist = [manual_app]
	#run_applist = [LAMP_apache_manual_app]
	#run_applist = [LAMP_mysql_manual_app]

def run_applist_str():
	s = ""
	for app in run_applist:
		s += " {}".format(app.appname)
	return s

if __name__ == '__main__':
	print_error_exit("not an executable module")
