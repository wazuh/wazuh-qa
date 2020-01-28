# Trigger script.
# This script generate the event that we need to analyse in the manager.
file = open("/fim_test/sha1_sum_file.txt","w")
file.write("Hello World\n")
file.write("This is our new text file\n")
file.close()