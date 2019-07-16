# Trigger script.
# This script generate the event that we need to analyse in the manager.
file_path_level_1 = "/fim_test/testing_directory_1/check_recursion_level_1_file.txt"
file_path_level_2 = "/fim_test/testing_directory_1/testing_directory_2/check_recursion_level_2_file.txt"

file = open(file_path_level_1,"a")
file.write("Modifying the file to get an alert!\n")
file.close()

file = open(file_path_level_2,"a")
file.write("Modifying the file to get an alert!\n")
file.close()