# Trigger script.
# This script generate the event that we need to analyse in the manager.
file = open("/fim_test/check_tags_file.txt","a")
file.write("Modifying the file to get an alert!\n")
file.close()