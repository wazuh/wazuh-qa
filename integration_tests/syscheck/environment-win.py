#!/usr/bin/python
# Testing FIM options work. Part I
# Add testing configuration to the end of ossec.conf
# And create, modify and delete files to generate alerts

import os, shutil
from stat import S_IREAD, S_IRGRP, S_IROTH, S_IWUSR
import time
import random, string
import subprocess

# Directories and options
#log_file = '/var/ossec/logs/ossec.log'
testing_dir = 'C:\\Users\\Administrator\\Documents\\testing_fim_options'
opt = ['t_frequency', 't_whodata', 't_realtime']
opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner', 'check_perm', \
    'check_mtime', 'check_attr', 'report_changes', 'tags', 'restrict', 'recursion_level']


# Generate random name to files
def generate_name():
    result = ""
    for i in range(0,5):
        result += random.choice(string.ascii_letters)
    return result


# Removes files and directories from previous tests
def check_test_directories():
    if os.path.isdir(testing_dir):
        shutil.rmtree(testing_dir, ignore_errors=True)
    os.mkdir(testing_dir)
    for i in opt:
        os.mkdir(testing_dir + '\\' + i)
        for j in opt_check:
            os.mkdir(testing_dir + '\\' + i + '\\' + j)


# Add test configuration in /var/ossec/etc/ossec.conf
def add_configuration():
    with open('C:\\Program Files (x86)\\ossec-agent\\ossec.conf','a') as f:
        f.write('\n' + '<ossec_config>\n')
        f.write('<syscheck>\n')
        f.write('<frequency>120</frequency>\n')
        for i in opt_check:
            if i == 'tags' or i == 'report_changes':
                f.write('<directories check_size="yes" {2}="yes">{0}\{1}\{2}</directories>\n'.format(testing_dir, opt[0], i))
                f.write('<directories check_size="yes" whodata="yes" {2}="yes">{0}\{1}\{2}</directories>\n'.format(testing_dir, opt[1], i))
                f.write('<directories check_size="yes" realtime="yes" {2}="yes">{0}\{1}\{2}</directories>\n'.format(testing_dir, opt[2], i))
            elif i == 'recursion_level':
                f.write('<directories check_size="yes" {2}="1">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[0], i))
                f.write('<directories check_size="yes" whodata="yes" {2}="1">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[1], i))
                f.write('<directories check_size="yes" realtime="yes" {2}="1">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[2], i))
            elif i == 'restrict':
                f.write('<directories check_size="yes" {2}="test$">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[0], i))
                f.write('<directories check_size="yes" whodata="yes" {2}="test$">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[1], i))
                f.write('<directories check_size="yes" realtime="yes" {2}="test$">{0}/{1}/{2}</directories>\n'.format(testing_dir, opt[2], i))
            else:
                f.write('<directories {2}="yes">{0}\{1}\{2}</directories>\n'.format(testing_dir, opt[0], i))
                f.write('<directories whodata="yes" {2}="yes">{0}\{1}\{2}</directories>\n'.format(testing_dir, opt[1], i))
                f.write('<directories realtime="yes" {2}="yes">{0}\{1}\{2}</directories>\n'.format(testing_dir, opt[2], i))
        f.write('</syscheck>\n')
        f.write('</ossec_config>\n')
        f.close()

# Create and modify files to generate alerts
def write_files(msg, archive):
    for i in opt:
        for j in opt_check:
            ff = open('{0}\\{1}\\{2}\\{3}'.format(testing_dir, i, j, archive), 'w')
            ff.write(msg)
            ff.close()


# Modify owner and/or group of files
def call_chown(owner, group, archive):
    for i in opt:
        for j in opt_check:
            shutil.chown('{0}\\{1}\\{2}\\{3}'.format(testing_dir, i, j, archive), owner, group)


# Modify permission
def change_perm(archive, perm):
    for i in opt:
        for j in opt_check:
            os.chmod('{0}\\{1}\\{2}\\{3}'.format(testing_dir, i, j, archive), perm)


def test_recursion_level():
    name = generate_name()
    for i in opt:
        os.mkdir(testing_dir + '\\' + i + '\\recursion_level\\level1')
        ff = open(testing_dir + '\\' + i + '\\recursion_level\\level1\\{0}'.format(name), 'w')
        ff.close()
        os.mkdir(testing_dir + '\\' + i + '\\recursion_level\\level1\\level2')
        ff = open(testing_dir + '\\' + i + '\\recursion_level\\level1\\level2\\{0}'.format(name), 'w')
        ff.close()


# Delete files
def delete_files(archive):
    for i in opt:
        for j in opt_check:
            os.remove('{0}\\{1}\\{2}\\{3}'.format(testing_dir, i, j, archive))


# Main
if __name__ == '__main__':

    time_to_sleep = 180
    file_name = generate_name()

    check_test_directories()
    print(' ----- ----- ----- ----- Check test directories --- DONE')
    add_configuration()
    print(' ----- ----- ----- ----- Add configuration --- DONE')
    os.system('taskkill.exe /f /im ossec-agent.exe')
    print(' ----- ----- ----- ----- Stop Wazuh --- DONE')
    #os.spawnv(os.P_DETACH, 'C:\\Program Files (x86)\\ossec-agent\\ossec-agent.exe', ['start'])
    subprocess.Popen(['C:\\Program Files (x86)\\ossec-agent\\ossec-agent.exe', 'start'], creationflags = subprocess.CREATE_NEW_CONSOLE)
    print(' ----- ----- ----- ----- Start Wazuh --- DONE')
    print(' ----- ----- ----- ----- Wait for syscheck to generate its database: it take a few minutes')
    time.sleep(60)
    #waiting_time('ossec-syscheckd: INFO: (6011): Initializing real time file monitoring engine.')
    file_name = generate_name()
    print(' ----- ----- ----- ----- Creating files ---')
    write_files('File created', file_name)
    time.sleep(30)
    print(' ----- ----- ----- ----- Modifying files ---')
    write_files('File modified', file_name)
    time.sleep(30)
    #print(' ----- ----- ----- ----- Modifying owner ---')
    #call_chown('Administrators', None, file_name)
    #time.sleep(time_to_sleep)
    time.sleep(30)
    print(' ----- ----- ----- ----- Modifying permission ---')
    change_perm(file_name, S_IREAD|S_IRGRP|S_IROTH)
    time.sleep(30)
    print(' ----- ----- ----- ----- Modifying permission ---')
    change_perm(file_name, S_IWUSR|S_IREAD)
    print(' ----- ----- ----- ----- Removing files ---')
    delete_files(file_name)
    time.sleep(30)
    print(' ----- ----- ----- ----- DONE ----- ----- ----- -----')
