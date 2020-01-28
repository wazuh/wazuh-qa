# Trigger script.
# This script generate the event that we need to analyse in the manager.
file = open("/fim_test/sha256_sum_file.txt","a")
file.write("Modifying the file to get an alert!\n")
file.close()