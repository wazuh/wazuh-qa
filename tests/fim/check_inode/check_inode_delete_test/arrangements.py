# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess

# files and dirs
test_file = "/fim_test/check_inode_file.txt"
test_dir  = "/fim_test"

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" check_inode="no" realtime="yes">/fim_test</directories></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# create test directory if don't exist
if not os.path.exists(test_dir):
    os.mkdir(test_dir)

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()

# create the file to modify it on trigger.py
file = open(test_file,"w")
file.write("Hello World\n")
file.write("This is our new text file\n")
file.close()
