# Arrangements script
# This script creates the environment needed to make the test
import os, time, subprocess

# append new config
config = '<ossec_config><syscheck><auto_ignore frequency="5" timeframe="60">yes</auto_ignore></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# restart wazuh-manager service
p = subprocess.Popen(["service", "wazuh-manager", "restart"])
p.wait()
