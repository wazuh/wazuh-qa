# Arrangements script
# This script creates the environment needed to make the test
import os, subprocess, pathlib

path_level_320 = "/fim_test/"

for i in range(1,322):
    path_level_320 += ("dir_" + str(i) + "/")

# path_level_320 = path_level_320[:1]

# append new config
config = '<ossec_config><syscheck><directories check_all="yes" recursion_level="320" realtime="yes">/fim_test</directories></syscheck></ossec_config>'

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

# create test directory if don't exist
pathlib.Path(path_level_320).mkdir(parents=True, exist_ok=True)

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()