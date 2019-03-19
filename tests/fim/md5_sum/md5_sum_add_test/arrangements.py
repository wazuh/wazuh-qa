# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" check_md5sum="no" realtime="yes">/fim_test</directories></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# create test directory if don't exist
if not os.path.exists("/fim_test"):
    os.mkdir("/fim_test")

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()
