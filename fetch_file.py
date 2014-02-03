#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details

import sys
import shutil
import argparse

from lib.core import *
from lib.objects import *

def main():
	# Parse arguments and define user's supplied hash 
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", dest="file", help="Hash of file (MD5 / SHA1 / SHA256)", required=True)
	
	args = parser.parse_args()
	usr_hash = args.file

	db_hash = sample()
	db_hash.define_by_hash(usr_hash)

	try:
		shutil.copy( db_hash.path, usr_hash )
		print usr_hash
	except:
		print "Failed to pull file"
			
if __name__ == "__main__":
	try:
	    main()
	except KeyboardInterrupt:
		db_shutdown()
		sys.exit(0)
    
    
