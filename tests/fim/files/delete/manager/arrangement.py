# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess

# append new config
config = '<ossec_config><syscheck><alert_new_files>no</alert_new_files></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# restart wazuh-manager service
p = subprocess.Popen(["service", "wazuh-manager", "restart"])
p.wait()
