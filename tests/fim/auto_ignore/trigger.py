import os, time

test_file = "/fim_test/check_auto_ignore_test.txt"

for i in range(1, 10):
    with open(test_file, "a") as file:
        file.write("Modification number " + str(i) + "\n")
    time.sleep(0.5)