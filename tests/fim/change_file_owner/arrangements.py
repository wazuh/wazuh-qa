# 5. Change owner file (same whodata, frequency and realtime)

import os
import time
import pwd
import grp
import subprocess


config = '<ossec_config><syscheck><directories check_all="yes" realtime="yes" check_owner="yes">/fim_test</directories></syscheck></ossec_config>'
test_file = "/fim_test/check_change_file_perm_test.txt"
test_dir = "/fim_test"

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

if not os.path.exists(test_dir):
    os.mkdir(test_dir)

file = open(test_file,"w") 
file.close()
    
uid = pwd.getpwnam("root").pw_uid
gid = grp.getgrnam("root").gr_gid
os.chown(test_file, uid, gid)

try:
    grp.getgrnam('wazuh')
except KeyError:
    os.system("groupadd -g 1005 wazuh")

try:
     pwd.getpwnam('wazuh')
except KeyError:
    os.system("useradd -g 1005 -u 1002 wazuh")

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()
