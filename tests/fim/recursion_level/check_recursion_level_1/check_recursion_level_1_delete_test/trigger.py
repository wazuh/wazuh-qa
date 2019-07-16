# Trigger script.
# This script generate the event that we need to analyse in the manager.

import os

file_path_level_1 = "/fim_test/testing_directory_1/check_recursion_level_1_file.txt"
file_path_level_2 = "/fim_test/testing_directory_1/testing_directory_2/check_recursion_level_2_file.txt"

if os.path.exists(file_path_level_1):
  os.remove(file_path_level_1)

if os.path.exists(file_path_level_2):
  os.remove(file_path_level_2)