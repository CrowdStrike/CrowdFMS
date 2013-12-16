#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details

import os
import sqlite3

# initialize new database
def db_initialize():
	db_notif.execute('''CREATE TABLE samples(
								sample_md5 varchar(255) NOT NULL,
								sample_sha1 varchar(255) NOT NULL,
								sample_sha256 varchar(255) NOT NULL,
								sample_ruleset text,
								sample_rulename text,
								sample_added int(20),
								sample_first_seen int(20),
								sample_detectionratio real(5),
								sample_size int(10),
								sample_path text NOT NULL
								)''')

	db_notif.execute('''CREATE TABLE rule_actions(
								rulename text NOT NULL,
								sys_command text NOT NULL
								)''')

	db_notif.execute('''CREATE TABLE ruleset_actions(
								rulesetname text NOT NULL,
								sys_command text NOT NULL
								)''')

	db_notif.commit()

# Check to see if file exists and if it does not, print and continue
def db_pre_check():
	if (os.path.isdir("./db") == False):
		os.mkdir("./db")

	try:
		with open( 'db/notification.db') as handle_db_check:
			return False
	except IOError:
		print " [+] Creating New Database"
		return True

# Gracefully Shutdown connection to DB
def db_shutdown():
	db_notif.close()
	
# On load of module 
bool_new_db = db_pre_check()
db_notif = sqlite3.connect('db/notification.db')

if (bool_new_db):
	db_initialize()	
