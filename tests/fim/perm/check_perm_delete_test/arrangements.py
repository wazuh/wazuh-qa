# Delete file without check_owner option enabled.

import os
import pwd
import grp
import subprocess

config = '<ossec_config><syscheck><directories check_all="yes" check_perm="no" realtime="yes">/fim_test</directories></syscheck></ossec_config>'
test_dir = "/fim_test"
test_file = "/fim_test/check_perm_delete_test.txt"

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

if not os.path.exists(test_dir):
    os.mkdir(test_dir)


file = open(test_file,"w") 
file.close()

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()
