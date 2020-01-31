# Trigger script.
# This script generate the event that we need to analyse in the manager.
file_path_level_0 = "/fim_test/check_recursion_level_0_file.txt"
file_path_level_1 = "/fim_test/testing_directory_1/check_recursion_level_1_file.txt"

file = open(file_path_level_0,"w")
file.write("Hello World\n")
file.write("This is our new text file\n")
file.close()

file = open(file_path_level_1,"w")
file.write("Hello World\n")
file.write("This is our new text file\n")
file.close()