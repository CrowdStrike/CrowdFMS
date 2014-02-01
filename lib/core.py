#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details

import sys
import os
import requests
import re
import json
import time
import subprocess
import fcntl

from lib.db import *

# Read ~/.virustotal and read the first line.  This file only needs the API string in it.
def func_set_api_key():
	try:
		if ( os.path.exists(os.path.expanduser('~') + '/.virustotal' ) ): 
			with open( os.path.expanduser('~') + '/.virustotal' ) as handle_api_file:
				return func_parse_api_key(handle_api_file.readlines())
		elif (  os.path.exists('.virustotal' ) ): 
			with open( '.virustotal' ) as handle_api_file:
				return func_parse_api_key(handle_api_file.readlines())
		else:
			sys.exit(" [X] Please Put API Key in ~/.virustotal or .virustotal")
	except IOError:
		sys.exit(" [X] Please Put API Key in ~/.virustotal or .virustotal")

# Parse the API key and exit if the API key contains any non [A-Za-z0-9]+
def func_parse_api_key(lst_tmp_key):
	str_tmp_key = "".join(lst_tmp_key).rstrip()
	if re.match("^[A-Za-z0-9]+$", str_tmp_key): 
		return str_tmp_key
	else:
		sys.exit(" [X] Problem with supplied API key formatting")
	
# Pull the JSON feed from VT and return dict to main
def func_pull_feed(str_api_key):
	req_user_agent = {'User-agent': 'VirusTotal FMS 1.0'}
	try:
		vt_request_results = requests.get("https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=%s" % str_api_key, headers=req_user_agent)
	except:
		return 0
	try:
		return json.loads(vt_request_results.content)
	except ValueError:
		print vt_request_results.content
		return 0

# Convert VT timestamps to Epoch Timestamp
def func_to_epoch(str_timestamp):
	try:
		format = '%Y-%m-%d %H:%M:%S'
		return int(time.mktime(time.strptime(str_timestamp.rstrip(), format)))
	except:
		return 1

# Download sample and store it to disk
def func_download_sample(str_api_key, str_path, str_hash):
	save_path = str_path + '/' + str_hash[:3] + "/" + str_hash[3:6] + "/" + str_hash[6:9] + "/"
	
	if not os.path.exists(save_path):	
		os.makedirs(save_path)
		
	req_user_agent = {'User-agent': 'VirusTotal FMS'}
	vt_request_results = requests.get("https://www.virustotal.com/intelligence/download/?hash=%s&apikey=%s" % (str_hash, str_api_key), headers=req_user_agent)
	

	with open(save_path + str_hash, "wb") as save_file:
		save_file.write(vt_request_results.content)
    
	return save_path + str_hash

# Pull array of all rule specific actions
def funct_parse_rule_actions():
		db_cursor = db_notif.cursor()
		tmp_action_dict = {}
		sql_rule_actions = 'SELECT rulename, sys_command FROM rule_actions'
		for tmp_row in db_cursor.execute( sql_rule_actions ):
			tmp_action_dict[str(tmp_row[0])] = str(tmp_row[1])
		
		return tmp_action_dict

# Pull array of all rule specific actions
def funct_run_rule_action(system_command, sample_path):
	if (os.path.isdir("./log") == False):
		os.mkdir("./log")
		
	handle_log_file = open("./log/external_commands.log" , "a")
	fcntl.flock(handle_log_file, fcntl.LOCK_EX)
	
	sys_command = system_command   % sample_path

	handle_log_file.write("[+] Executing %s \n" % sys_command)
	print " [+] Executing %s " % sys_command

	subprocess.Popen(sys_command,stdout=handle_log_file, stderr=handle_log_file, shell=True)
	print " [+] External command execution complete"

	handle_log_file.close()
	return 0;
       

                
                
                
                
