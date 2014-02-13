#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details

import sys
import os
import thread
import time

from lib.core import funct_parse_rule_actions, func_pull_feed, func_to_epoch, func_download_sample, func_set_api_key, funct_run_rule_action
from lib.objects import sample
from lib.db import db_shutdown


LOOP_TIME = 300
STORAGE_PATH = "./samples/"
RUN = True
API_KEY = func_set_api_key()
DEFAULT_ACTION = ""

def main():
	print " [+] Starting CrowdFMS"
	while(RUN):
		print " [+] Starting Loop"
		loop_pull_feed()
		print " [S] Sleeping %s" % LOOP_TIME
		time.sleep(LOOP_TIME)

def startup():
	global STORAGE_PATH
	if (os.path.isdir(STORAGE_PATH) == False):
		os.mkdir(STORAGE_PATH)


def loop_pull_feed():
	tmp_oldest = 999999999999
	tmp_newest = 0
	global LOOP_TIME
	
	rule_actions = funct_parse_rule_actions()
	
	json_notif_feed = func_pull_feed(API_KEY)
	if (json_notif_feed == 0):
		print "Problem pulling feed.  Sleeping..."
		return

	for vt_notif in json_notif_feed["notifications"]:

		if (func_to_epoch(vt_notif["date"]) > tmp_newest):
			tmp_newest = func_to_epoch(vt_notif["date"])
			
		if (func_to_epoch(vt_notif["date"]) < tmp_oldest):
			tmp_oldest = func_to_epoch(vt_notif["date"])			
	
	
		try:
			tmp_sample = sample()
			tmp_sample.define_sample(
							vt_notif["md5"], 
							vt_notif["sha1"], 
							vt_notif["sha256"], 
							vt_notif["ruleset_name"], 
							vt_notif["subject"], 
							func_to_epoch(vt_notif["date"]),
							func_to_epoch(vt_notif["first_seen"]), 
							(float(vt_notif["positives"]) / float(vt_notif["total"])),
							vt_notif["size"], 
		
							)

		except KeyError:
			sys.exit(" [X] Problem parsing VT feed")
		
		if (tmp_sample.check_new()):
			sample_path = func_download_sample(API_KEY, STORAGE_PATH, vt_notif["md5"])
			tmp_sample.set_path( sample_path )
			
			if ( tmp_sample.insert_db() == True ):
				tmp_sample.print_short()
				if '%s' in DEFAULT_ACTION:
					try:
						thread.start_new_thread( funct_run_rule_action, (DEFAULT_ACTION, sample_path ) )
					except:
						funct_run_rule_action( DEFAULT_ACTION , sample_path )				
				
				
				
				if (str(vt_notif["subject"]) in rule_actions ):
					try:
						thread.start_new_thread( funct_run_rule_action, (rule_actions[vt_notif["subject"]], sample_path ) )
					except:
						funct_run_rule_action( rule_actions[vt_notif["subject"]] , sample_path )
				
			else:
				print " [-] Problem submitting sample to DB"
	
	if ( ((tmp_newest - tmp_oldest) < LOOP_TIME) and (LOOP_TIME > 60) ) :
		LOOP_TIME = (LOOP_TIME / 2)
		
if __name__ == "__main__":
	try:
		startup()
		main()
	except KeyboardInterrupt:
		db_shutdown()
		sys.exit(" [X] Shutting Down")

