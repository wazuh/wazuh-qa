# 7. Change permission (from 644 to 421)
#arrangements.py

import os, time, subprocess

test_file = "/fim_test/check_change_file_perm_test.txt"
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

if not os.path.exists(test_file): # comprueba que exista y se pueda escribir
    file = open(test_file,"w")
    file.close()
os.chmod(test_file, 644)
