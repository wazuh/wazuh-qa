# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" check_size="no" realtime="yes">/fim_test</directories></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# create test directory if don't exist
if not os.path.exists("/fim_test"):
    os.mkdir("/fim_test")

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()

# create the file to modify it on trigger.py
file = open("/fim_test/check_size_file.txt","w")
file.write("Hello World\n")
file.write("This is our new text file\n")
file.close()
