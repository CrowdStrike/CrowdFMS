#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details

import argparse

from lib.objects import *
from lib.core import *

def main():
	# Parse arguments and define user's supplied hash 
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", dest="file", help="Hash of file (MD5 / SHA1 / SHA256", required=True)
	
	args = parser.parse_args()
	usr_hash = args.file
	
	db_hash = sample()
	db_hash.define_by_hash(usr_hash)
	db_hash.print_self()
	print "     Path            : %s" % db_hash.path


if __name__ == "__main__":
	try:
	    main()
	except KeyboardInterrupt:
		db_shutdown()
		sys.exit(0)
    
    
