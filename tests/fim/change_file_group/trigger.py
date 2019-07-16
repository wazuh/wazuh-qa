# 6. Change group file

import os
import pwd
import grp

test_file = "/fim_test/check_change_file_group_test.txt"
gid = grp.getgrnam("wazuh").gr_gid
os.chown(test_file, -1, gid)

