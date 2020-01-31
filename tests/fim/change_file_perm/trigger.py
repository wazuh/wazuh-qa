# 7. Change permission (from 644 to 421)

import os, time

test_file = "/fim_test/check_change_file_perm_test.txt"

os.chmod(test_file, 421)
