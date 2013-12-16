#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details


import sys
import os
import argparse

from lib.db import *

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-c", "--command_path", help="Path to command to exec", required=True)
	parser.add_argument("-y", "--yara_rule", help="Yara Rule to match", required=True)
	
	args = parser.parse_args()
	command = args.command_path
	yara_rule = args.yara_rule

	if '%s' not in command:
		sys.exit("Please format the command with a %s where the path to the sample should be inserted")
	
	db_cursor = db_notif.cursor()
	sql_check_yara = "SELECT rulename FROM rule_actions WHERE rulename = ?"  
	db_cursor.execute( sql_check_yara, ([yara_rule]) )
	
	check_result = db_cursor.fetchone()
	
	if check_result is not None:
		sys.exit(" [X] Filter already exists for rule %s" % yara_rule)
	else:
		sql_insert = "INSERT INTO rule_actions VALUES ( ?, ?)"
		db_notif.execute(sql_insert, (yara_rule, command))
		db_notif.commit()
	
	print "Action added for %s (%s)" % (yara_rule, command)

if __name__ == "__main__":
	try:
	    main()
	except KeyboardInterrupt:
		db_shutdown()
		sys.exit(0)
    
    
