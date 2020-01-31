# Add file without check_owner option enabled.

import os

test_file = "/fim_test/check_group_add_test.txt"
file = open(test_file,"w") 
file.close()
