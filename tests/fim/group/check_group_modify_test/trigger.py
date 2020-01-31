# Modify file without check_owner option enabled.

import os
import pwd
import grp

test_file = "/fim_test/check_group_modify_test.txt"
gid = grp.getgrnam("wazuh").gr_gid
os.chown(test_file, -1, gid)
