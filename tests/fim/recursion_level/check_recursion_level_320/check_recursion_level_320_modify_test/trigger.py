# Trigger script.
# This script generate the event that we need to analyse in the manager.
path_level_320 = "/fim_test/"

for i in range(1,322):
    path_level_320 += ("dir_" + str(i) + "/")
    if i == 320:
        file_path_level_320 = path_level_320 + "check_recursion_level_320_file.txt"
    if i == 321:
        file_path_level_321 = path_level_320 + "check_recursion_level_321_file.txt"

file = open(file_path_level_320,"a")
file.write("Modifying the file to get an alert!\n")
file.close()

file = open(file_path_level_321,"a")
file.write("Modifying the file to get an alert!\n")
file.close()