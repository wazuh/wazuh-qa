# Trigger script.
# This script generate the event that we need to analyse in the manager.
import time
time.sleep(3)
file = open("/fim_test/md5_sum_file.txt","a")
file.write("Modifying the file to get an alert!\n")
file.close()