# 5. Change owner file (same whodata, frequency and realtime)

import os
import pwd
import grp

test_file = "/fim_test/check_change_file_perm_test.txt"

uid = pwd.getpwnam("wazuh").pw_uid
os.chown(test_file, uid, -1)
