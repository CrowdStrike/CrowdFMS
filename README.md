Copyright (C) 2013 CrowdStrike, Inc.
This file is subject to the terms and conditions of the BSD License.
See the file LICENSE in the main directory for details


CrowdFMS is a framework for automating collection and processing of samples from
VirusTotal, by leveraging the Private API system.   This framework automatically 
downloads recent samples, which triggered an alert on the users YARA notification feed. 

Users can also specify a command to execute on these newly downloaded samples, 
based on their YARA rule name.  For example, a user can specify that all samples 
that matched the YARA rule “Zeus”, be automatically submitted to Cuckoo sandbox.


Python Modules:
 - sqlite3
 - shutil
 - argparse
 - requests
 - re
 - json
 - requests

Please also place your API key in either .virustotal or ~/.virustotal

Usage and Tools:
 crowdfms.py - Primary sample collection system

 sample_details - Fetch details about a sample stored in the local database 
  + Usage: sample_details.py -f -HASH-       # Hash can be either MD5, SHA1 or SHA256

 fetch_file - copy file from database to current working directory
  + Usage: fetch_file -f -HASH-   # Hash can be either MD5, SHA1 or SHA256 

 add_action - Add action to preform on new sample rule metch
  + Usage: add_action -y -Yara Rule Name- -c -Command to Execute-   # Command to Execute must contain %s where sample path should go
 
 add_action - Add action to preform on new sample rule metch
  + Usage: add_action -y -Yara Rule Name- -c -Command to Execute-   # Command to Execute must contain %s where sample path should go

 list_actions - List all Yara -> matches
  + Usage: list_actions
