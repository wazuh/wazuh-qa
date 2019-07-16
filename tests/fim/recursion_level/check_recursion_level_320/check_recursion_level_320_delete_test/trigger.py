# Trigger script.
# This script generate the event that we need to analyse in the manager.

import os

path_level_320 = "/fim_test/"

for i in range(1,322):
    path_level_320 += ("dir_" + str(i) + "/")
    if i == 320:
        file_path_level_320 = path_level_320 + "check_recursion_level_320_file.txt"
    if i == 321:
        file_path_level_321 = path_level_320 + "check_recursion_level_321_file.txt"

if os.path.exists(file_path_level_320):
  os.remove(file_path_level_320)

if os.path.exists(file_path_level_321):
  os.remove(file_path_level_321)