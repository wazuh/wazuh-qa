# Modify file without check_owner option enabled.

import os
import pwd
import grp

test_file = "/fim_test/check_owner_modify_test.txt"
uid = pwd.getpwnam("wazuh").pw_uid
os.chown(test_file, uid, -1)
