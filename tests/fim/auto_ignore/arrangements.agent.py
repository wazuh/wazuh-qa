# Arrangements script
# This script creates the environment needed to make the test
import os, time, subprocess

test_file = "/fim_test/check_auto_ignore_test.txt"
test_dir  = "/fim_test"

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" realtime="yes">/fim_test</directories></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# create test directory if don't exist
if not os.path.exists(test_dir):
    os.mkdir(test_dir)

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()

file = open(test_file,"w")
file.close()
