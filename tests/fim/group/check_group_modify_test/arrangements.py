# Modify file without check_owner option enabled.

import os
import pwd
import grp
import subprocess

config = '<ossec_config><syscheck><directories check_all="yes" check_group="no" realtime="yes">/fim_test</directories></syscheck></ossec_config>'
test_dir = "/fim_test"
test_file = "/fim_test/check_group_modify_test.txt"

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

if not os.path.exists(test_dir):
    os.mkdir(test_dir)

file = open(test_file,"w")
file.close()

try:
    grp.getgrnam('wazuh')
except KeyError:
    os.system("groupadd -g 1005 wazuh")

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()
