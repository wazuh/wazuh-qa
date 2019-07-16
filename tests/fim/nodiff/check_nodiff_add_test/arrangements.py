# coding=utf-8
# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" report_changes="yes" realtime="yes">/fim_test</directories><nodiff>/fim_test/check_nodiff_file.txt</nodiff></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# create test directory if don't exist
if not os.path.exists("/fim_test"):
    os.mkdir("/fim_test")

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()