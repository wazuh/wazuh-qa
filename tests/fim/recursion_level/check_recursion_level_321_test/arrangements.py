# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess, pathlib

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" recursion_level="321" realtime="yes">/fim_test</directories></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()