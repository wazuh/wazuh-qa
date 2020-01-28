# Modify file without check_owner option enabled.

import os
import pwd
import grp

test_file = "/fim_test/check_perm_modify_test.txt"
os.chmod(test_file, 421)
