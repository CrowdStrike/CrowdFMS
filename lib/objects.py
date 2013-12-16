#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details

import sys
from lib.db import *

# Create an object that defines each of the notifications from VT
class sample(object):
	# Initialize new sample
	def __init__(self):
		pass

	# Define attributes of notification 
	def define_sample(self, md5, sha1, sha256, ruleset_name, rule_name, notificaiton_date, first_seen, detection_ratio, size):
		self.md5 = md5
		self.sha1 = sha1
		self.sha256 = sha256
		self.ruleset_name = ruleset_name
		self.rule_name = rule_name
		self.notificaiton_date = notificaiton_date
		self.first_seen = first_seen
		self.detection_ratio = detection_ratio
		self.size = size

	# Populate attributes of sample by pulling them from the DB
	def define_by_hash(self, usr_hash):
		db_cursor = db_notif.cursor()
		
		# Parse length of user supplied hash to determine hash type
		if ( usr_hash.isalnum() == False ):
			sys.exit("Invalid Hash.")
		elif (len(usr_hash) == 32):
			sql_select_details = "SELECT * FROM samples WHERE sample_md5 = ? "
		elif (len(usr_hash) == 40):
			sql_select_details = "SELECT * FROM samples WHERE sample_sha1 = ? "
		elif (len(usr_hash) == 64):
			sql_select_details = "SELECT * FROM samples WHERE sample_sha256 = ? "
		else:
			sys.exit("Invalid Hash-")

		db_cursor.execute(sql_select_details, ([usr_hash]))
		
		db_result = db_cursor.fetchone()
		if db_result is None:
			sys.exit("Sample Not Found")
		else:
			try:
				self.define_sample(
							db_result[0],
							db_result[1],
							db_result[2],
							db_result[3],
							db_result[4],
							db_result[5],
							db_result[6],
							db_result[7],
							db_result[8]
							)
				self.set_path(db_result[9])			
			except:
				sys.exit("Problem Parsing Hash")
				
				
	'''
		long printing of notification object
		ex:
		 [*] MD5             : 00000000000000000000000000000000
		     SHA1            : 0000000000000000000000000000000000000000
		     SHA256          : 0000000000000000000000000000000000000000000000000000000000000000
		     Ruleset Name    : TestRuleSet
		     Rule Name       : TestRule
		     Notific. Date   : 000000000
		     First Seen      : 000000000
		     Detection Ratio : .00
		     Size            : 000 
	'''
	def print_self(self):
		print " [*] MD5             : %s" % self.md5
		print "     SHA1            : %s" % self.sha1
		print "     SHA256          : %s" % self.sha256
		print "     Ruleset Name    : %s" % self.ruleset_name
		print "     Rule Name       : %s" % self.rule_name
		print "     Notific. Date   : %s" % self.notificaiton_date
		print "     First Seen      : %s" % self.first_seen
		print "     Detection Ratio : %s" % self.detection_ratio
		print "     Size            : %s" % self.size 

	'''
		short printing of notification object
		ex: 
		 [*] MD5 : 00000000000000000000000000000000 (Rulename : Test)
	'''
	def print_short(self):
		print " [*] MD5 : %s (Rulename : %s) " % (self.md5, self.rule_name)
		
	# set path of sample
	def set_path(self, path):
		self.path = path
		

	# insert sample into database for storage
	def insert_db(self):
		values = [
				self.md5, 
				self.sha1, 
				self.sha256, 
				self.ruleset_name, 
				self.rule_name, 
				self.notificaiton_date, 
				self.first_seen,
				self.detection_ratio,
				self.size,  
				self.path
			]
		
		sql_insert = "INSERT INTO samples VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )"
		try: 
			
			db_notif.execute(sql_insert, (values))
			db_notif.commit()
			return True
		except:
			return False

	# Check to see if sample already exists in DB
	def check_new(self):
		db_cursor = db_notif.cursor()
		
		sql_check_new = "SELECT sample_md5 FROM samples WHERE sample_md5=? and sample_rulename=?"
		
		db_cursor.execute(sql_check_new, (self.md5, self.rule_name))
		
		if db_cursor.fetchone() is None:
			return True
		else:
			return False

	


		
