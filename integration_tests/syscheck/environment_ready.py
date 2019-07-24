#!/usr/bin/python
# Testing FIM options work. Part I
# Add testing configuration to the end of ossec.conf
# And create, modify and delete files to generate alerts

import os, shutil
import time
import random, string


# Directories and options
log_file = '/var/ossec/logs/ossec.log'
testing_dir = '/home/lopezziur/testing_fim_options'
opt = ['t_frequency', 't_whodata', 't_realtime']
opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner', 'check_group', 'check_perm', \
    'check_mtime', 'check_inode', 'report_changes']


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
    with open(log_file, 'r') as file:
        for line in log_file:
            if line.find(log):
                result = result + 1
    return result


# Removes files and directories from previous tests
def check_test_directories():
    if os.path.isdir(testing_dir):
        shutil.rmtree(testing_dir)
    os.mkdir(testing_dir)
    for i in opt:
        os.mkdir(testing_dir + '/' + i)
        for j in opt_check:
            os.mkdir(testing_dir + '/' + i + '/' + j)


# Add test configuration in /var/ossec/etc/ossec.conf
def add_configuration():
    with open('/var/ossec/etc/ossec.conf','a') as f:
        f.write('\n' + '<ossec_config>\n')
        f.write('<syscheck>\n')
        f.write('<frequency>120</frequency>\n')
        for i in opt_check:
            f.write('<directories {2}="yes">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[0], i))
            f.write('<directories whodata="yes" {2}="yes">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[1], i))
            f.write('<directories realtime="yes" {2}="yes">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[2], i))
        f.write('</syscheck>\n')
        f.write('</ossec_config>\n')
        f.close()


# Create and modify files to generate alerts
def write_files(msg, archive):
    for i in opt:
        for j in opt_check:
            ff = open('{0}/{1}/{2}/{3}'.format(testing_dir, i, j, archive), 'w')
            ff.write(msg)
            ff.close()


# Modify inode to generate alerts
def modify_inode(archive):
    delete_files(archive)
    write_files('File created', 'testing.txt')
    write_files('File created', 'testing.txt')


# Modify owner and/or group of files
def call_chown(owner, group, archive):
    for i in opt:
        for j in opt_check:
            shutil.chown('{0}/{1}/{2}/{3}'.format(testing_dir, i, j, archive), owner, group)


# Modify permission
def change_perm(perm, archive):
    for i in opt:
        for j in opt_check:
            os.chmod('{0}/{1}/{2}/{3}'.format(testing_dir, i, j, archive), perm)


# Delete files
def delete_files(archive):
    for i in opt:
        for j in opt_check:
            os.remove('{0}/{1}/{2}/{3}'.format(testing_dir, i, j, archive))


# Main
if __name__ == '__main__':

    time_to_sleep = 180
    file_name = generate_name()

    check_test_directories()
    print(' ----- ----- ----- ----- Check test directories --- DONE')
    add_configuration()
    print(' ----- ----- ----- ----- Add configuration --- DONE')
    print(' ----- ----- ----- ----- Restarting Wazuh')
    try:
        os.system('/var/ossec/bin/ossec-control restart')
        print(' ----- ----- ----- ----- Restart Wazuh --- DONE')
    except:
        print(' ----- ----- ----- ----- ERROR --- Can not restart Wazuh')
    print(' ----- ----- ----- ----- Wait for syscheck to generate its database: it take a few minutes')

    #waiting_time('ossec-syscheckd: INFO: (6011): Initializing real time file monitoring engine.')
    time.sleep(60)
    file_name = generate_name()
    print(' ----- ----- ----- ----- Creating files ---')
    write_files('File created', file_name)
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
    print(' ----- ----- ----- ----- Removing files ---')
    delete_files(file_name)
    time.sleep(time_to_sleep)
    print(' ----- ----- ----- ----- DONE ----- ----- ----- -----')

