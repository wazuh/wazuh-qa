#!/usr/bin/python
# Testing FIM options work. Part I
# Add testing configuration to the end of ossec.conf
# And create files, modify files, modify inodes, change owner and group, change permision, and delete files to generate alerts.
# Run in Windows


import os, sys, shutil, subprocess
from stat import S_IREAD, S_IRGRP, S_IROTH, S_IWUSR
import time, random, string


# Directories and options
testing_dir = 'C:\\Users\\Administrator\\Documents\\testing_fim_options'
opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', \
    'check_owner', 'check_perm', 'check_mtime', 'check_attrs']


# Generate random name to files
def generate_name():
    result = ""
    for i in range(0,5):
        result += random.choice(string.ascii_letters)
    return result


# Removes files and directories from previous tests
def check_test_directories():
    if os.path.isdir(testing_dir):
        shutil.rmtree(testing_dir)
    os.mkdir(testing_dir)
    for j in opt_check:
        os.mkdir(testing_dir + '\\' + j)


# Add test configuration in /var/ossec/etc/ossec.conf
def add_configuration(mode):
    with open('C:\\Program Files (x86)\\ossec-agent\\ossec.conf','a') as f:
        f.write('\n' + '<ossec_config>\n')
        f.write('<syscheck>\n')

        if mode == 'frequency':
            f.write('<frequency>120</frequency>\n')
            f.write('<directories check_size="yes" restrict="test$">{0}</directories>\n'.format(testing_dir))
            for i in opt_check:
                f.write('<directories recursion_level="1" tags="testing" report_changes="yes" {1}="yes">{0}\{1}</directories>\n'.format(testing_dir,i))
        else:
            f.write('<directories check_size="yes" restrict="test$" {1}="yes">{0}</directories>\n'.format(testing_dir, mode))
            for i in opt_check:
                f.write('<directories recursion_level="1" tags="testing" report_changes="yes" {2}="yes" {1}="yes">{0}\{1}</directories>\n'.format(testing_dir,i, mode))
        
        f.write('</syscheck>\n')
        f.write('</ossec_config>\n')
        f.close()

# Generate events:
def write_files(msg, archive):
    for j in opt_check:
        ff = open('{0}\\{1}\\{2}'.format(testing_dir, j, archive), 'w')
        ff.write(msg)
        ff.close()

def call_chown(owner, group, archive):
    for j in opt_check:
        shutil.chown('{0}\\{1}\\{2}'.format(testing_dir, j, archive), owner, group)

def change_perm(archive, perm):
    for j in opt_check:
        os.chmod('{0}\\{1}\\{2}'.format(testing_dir, j, archive), perm)

def test_recursion_level():
    name = generate_name()
    for i in opt_check:
        os.mkdir('{0}\\{1}\\level1'.format(testing_dir, i))
        os.mkdir('{0}\\{1}\\level1\\level2'.format(testing_dir, i))
        ff = open('{0}\\{1}\\level1\\level2\\{2}'.format(testing_dir, i, name), 'w')
        ff.close()

def delete_files(archive):
    for j in opt_check:
        os.remove('{0}\\{1}\\{2}'.format(testing_dir, j, archive))


####
if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('frequency, realtime or whodata')

    else:
        mode = sys.argv[1]
        if mode == 'frequency': time_to_sleep = 180
        else: time_to_sleep = 40
        file_name = generate_name()
        check_test_directories()
        print(' ----- ----- ----- ----- Check test directories --- DONE')
        add_configuration(mode)
        print(' ----- ----- ----- ----- Add configuration --- DONE')
        os.system('taskkill.exe /f /im ossec-agent.exe')
        print(' ----- ----- ----- ----- Stop Wazuh --- DONE')
        subprocess.Popen(['C:\\Program Files (x86)\\ossec-agent\\ossec-agent.exe', 'start'], creationflags = subprocess.CREATE_NEW_CONSOLE)
        print(' ----- ----- ----- ----- Start Wazuh --- DONE')
        print(' ----- ----- ----- ----- Wait for syscheck to generate its database: it take a few minutes')
        time.sleep(60)
        file_name = generate_name()
        print(' ----- ----- ----- ----- Creating files ---')
        write_files('File created', file_name)
        test_recursion_level()
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying files ---')
        write_files('File modified', file_name)
        time.sleep(time_to_sleep)
        #print(' ----- ----- ----- ----- Modifying owner ---')
        #call_chown('Administrators', None, file_name)
        #time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying attributes ---')
        change_perm(file_name, S_IREAD|S_IRGRP|S_IROTH)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- Modifying attributes ---')
        change_perm(file_name, S_IWUSR|S_IREAD)
        print(' ----- ----- ----- ----- Removing files ---')
        delete_files(file_name)
        time.sleep(time_to_sleep)
        print(' ----- ----- ----- ----- DONE ----- ----- ----- -----')
