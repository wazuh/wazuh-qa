#!/usr/bin/python
# Testing FIM options work. Part I
# Add testing configuration to the end of ossec.conf
# And create files, modify files, modify inodes, change owner and group, change permision, and delete files to generate alerts.
# Run in Linux

import os, sys, shutil
import time, random, string


# Directories and options
log_file = '/var/ossec/logs/ossec.log'
testing_dir = '/home/lopezziur/testing_fim_options'
opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner', \
    'check_group', 'check_perm', 'check_mtime', 'check_inode']


# Generate random name to files
def generate_name():
    result = ""
    for i in range(0,5):
        result += random.choice(string.ascii_letters)
    return result


# Waiting time
def waiting_time(log):
    count = counter(log)
    print(count)
    while True:
        print(counter(log))
        if count != counter(log):
            break
        else:
            time.sleep(5)

def counter(log):
    result = 0
    with open(log_file, 'r') as f:
        for line in f:
            if line.find(log):
                result += 1
    f.close()
    return result


# Removes files and directories from previous tests
def check_test_directories():
    if os.path.isdir(testing_dir):
        shutil.rmtree(testing_dir)
    os.mkdir(testing_dir)
    for j in opt_check:
        os.mkdir('{0}/{1}'.format(testing_dir, j))


# Add test configuration in /var/ossec/etc/ossec.conf
def add_configuration(mode):
    with open('/var/ossec/etc/ossec.conf','a') as f:
        f.write('\n' + '<ossec_config>\n')
        f.write('<syscheck>\n')
        if mode == 'frequency':
            f.write('<frequency>120</frequency>\n')
            f.write('<directories check_size="yes" restrict="test$">{0}</directories>\n'.format(testing_dir))
            for i in opt_check:
                f.write('<directories recursion_level="1" tags="testing" report_changes="yes" {1}="yes">{0}/{1}</directories>\n'.format(testing_dir,i))
        else:
            f.write('<directories check_size="yes" restrict="test$" {1}="yes">{0}</directories>\n'.format(testing_dir, mode))
            for i in opt_check:
                f.write('<directories recursion_level="1" tags="testing" report_changes="yes" {2}="yes" {1}="yes">{0}/{1}</directories>\n'.format(testing_dir,i, mode))
        f.write('</syscheck>\n')
        f.write('</ossec_config>\n')
        f.close()


# Generate events:
def write_files(msg, archive):
    for j in opt_check:
        ff = open('{0}/{1}/{2}'.format(testing_dir, j, archive), 'w')
        ff.write(msg)
        ff.close()

def modify_inode(archive):
    delete_files(archive)
    write_files('File created', 'testing.txt')
    write_files('File created', archive)

def call_chown(owner, group, archive):
    for j in opt_check:
        shutil.chown('{0}/{1}/{2}'.format(testing_dir, j, archive), owner, group)

def change_perm(perm, archive):
    for j in opt_check:
        os.chmod('{0}/{1}/{2}'.format(testing_dir, j, archive), perm)

def test_recursion_level():
    name = generate_name()
    for i in opt_check:
        os.mkdir('{0}/{1}/level1'.format(testing_dir, i))
        os.mkdir('{0}/{1}/level1/level2'.format(testing_dir, i))
        ff = open('{0}/{1}/level1/level2/{2}'.format(testing_dir, i, name), 'w')
        ff.close()

def delete_files(archive):
    for j in opt_check:
        os.remove('{0}/{1}/{2}'.format(testing_dir, j, archive))


####
if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('frequency, realtime or whodata')

    else:
        file_name = generate_name()
        mode = sys.argv[1]
        if mode == 'frequency': time_to_sleep = 180
        else: time_to_sleep = 40

        check_test_directories()
        print(' ----- ----- ----- ----- Check test directories --- DONE')
        add_configuration(mode)
        print(' ----- ----- ----- ----- Add configuration --- DONE')
        print(' ----- ----- ----- ----- Restarting Wazuh')
        os.system('/var/ossec/bin/ossec-control restart')
        print(' ----- ----- ----- ----- Wait for syscheck to generate its database: it take a few minutes')
        #waiting_time('ossec-syscheckd: INFO: (6011): Initializing real time file monitoring engine.')
        time.sleep(60)
        file_name = generate_name()
        print(' ----- ----- ----- ----- Creating files ---')
        write_files('File created', file_name)
        ff = open('{0}restrict.txt'.format(testing_dir), 'w')
        ff.close()
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying inode ---')
        modify_inode(file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying files ---')
        write_files('File modified', file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying owner ---')
        call_chown('ossec', None, file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying group ---')
        call_chown(None, 'ossec', file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying group and owner ---')
        call_chown('root', 'root', file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying permission ---')
        change_perm(777, file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Test recursion-level ---')
        test_recursion_level()
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Removing files ---')
        delete_files(file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- DONE ----- ----- ----- -----')
