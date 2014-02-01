#!/usr/bin/env python
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the BSD License.
# See the file LICENSE in the main directory for details


import sys
import os

from lib.db import db_shutdown
from lib.core import funct_parse_rule_actions

def main():
	rule_actions = funct_parse_rule_actions()
	print " [!] %-*s: ( Command )\n" % (40, "Signature")
	for rule in rule_actions.keys():
		print " [+] %-*s: %s " % (40,rule, rule_actions[rule])

if __name__ == "__main__":
	try:
	    main()
	except KeyboardInterrupt:
		db_shutdown()
		sys.exit(0)
    
    
