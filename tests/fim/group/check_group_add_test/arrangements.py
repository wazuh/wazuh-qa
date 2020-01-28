# Add file without check_owner option enabled.

import os
import pwd
import grp
import subprocess

config = '<ossec_config><syscheck><directories check_all="yes" check_group="no" realtime="yes">/fim_test</directories></syscheck></ossec_config>'
test_dir = "/fim_test"

with open("/var/ossec/etc/ossec.conf", "a") as conf:
    conf.write(config)

if not os.path.exists(test_dir):
    os.mkdir(test_dir)

# restart wazuh-agent service
p = subprocess.Popen(["service", "wazuh-agent", "restart"])
p.wait()
