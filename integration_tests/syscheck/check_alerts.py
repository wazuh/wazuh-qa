#!/usr/bin/python
# Testing FIM options work. Part II
# Checks that alerts generate in part I are correct.


import json
import os


# Directories and options
alerts_directory = '/var/ossec/logs/alerts/alerts.json'
testing_dir = '/home/lopezziur/testing_fim_options'
opt = ['t_frequency', 't_whodata', 't_realtime']
opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner', 'check_group', 'check_perm', \
    'check_mtime', 'check_inode']


# Syscheck alert fields
syscheck_fiels = {}
syscheck_fiels['check_all_add'] = ['path', 'size_after', 'perm_after', 'uid_after', 'gid_after', 'md5_after', 'sha1_after', 'sha256_after', 'uname_after', 'gname_after', \
    'mtime_after', 'inode_after', 'event'] # check_all - add file
syscheck_fiels['check_sum_add'] = ['path', 'md5_after', 'sha1_after', 'sha256_after', 'event'] # check_sum - add file
syscheck_fiels['check_md5sum_add'] = ['path', 'md5_after', 'event'] # check_md5sum - add file
syscheck_fiels['check_sha1sum_add'] = ['path', 'sha1_after', 'event'] # check_sha1sum - add file
syscheck_fiels['check_sha256sum_add'] = ['path', 'sha256_after', 'event'] # check_sha256sum - add file
syscheck_fiels['check_size_add'] = ['path', 'event', 'size_after'] # check_size - add file
syscheck_fiels['check_owner_add'] = ['path', 'event', 'uid_after','uname_after'] # check_ownwer - add file
syscheck_fiels['check_group_add'] = ['path', 'event', 'gid_after','gname_after'] # check_group -add file
syscheck_fiels['check_perm_add'] = ['path', 'event', 'perm_after'] # check_perf - add file
syscheck_fiels['check_mtime_add'] = ['path', 'event', 'mtime_after'] # check_mtime - add file
syscheck_fiels['check_inode_add'] = ['path', 'event', 'inode_after'] # check_inode - add file
syscheck_fiels['check_all_modify'] = ['path', 'event', 'inode_after', 'size_before', 'size_after', 'perm_after', 'uid_after', 'gid_after', 'md5_before', 'md5_after', 'sha1_before', \
    'sha1_after', 'sha256_before', 'sha256_after', 'uname_after', 'gname_after', 'mtime_before', 'mtime_after'] # check_all - modify file
syscheck_fiels['check_sum_modify'] = ['path', 'event', 'md5_before', 'md5_after', 'sha1_before', 'sha1_after', 'sha256_before', 'sha256_after'] # check_sum -modifiy file
syscheck_fiels['check_md5sum_modify'] = ['path', 'event', 'md5_before', 'md5_after'] # check_md5sum - modify_file
syscheck_fiels['check_sha1sum_modify'] = ['path', 'event', 'sha1_before', 'sha1_after'] # check_sha1sum - modify file
syscheck_fiels['check_sha256sum_modify'] = ['path', 'event', 'sha256_before', 'sha256_after'] # check_sha256 - modify file
syscheck_fiels['check_size_modify'] = ['path', 'event', 'size_before', 'size_after'] # check_size - modify file
syscheck_fiels['check_mtime_modify'] = ['path', 'event', 'mtime_after', 'mtime_before'] # check_mtime - modify file
syscheck_fiels['check_owner_modify'] = ['path', 'event', 'uid_before', 'uid_after', 'uname_before', 'uname_after'] # check_owner - modify owner
syscheck_fiels['check_group_modify'] = ['path', 'event', 'gid_before', 'gid_after', 'gname_before', 'gname_after'] # check_group -modify group
syscheck_fiels['check_perm_modify'] = ['path', 'perm_before', 'perm_after', 'event']
syscheck_fiels['check_inode_modify'] = ['path', 'event', 'inode_after', 'inode_before']


# Check alerts when file is deleted
def check_delete(path):
    with open(alerts_directory, 'r') as alerts:
        for line in alerts:
            alert = json.loads(line)
            if 'syscheck' in alert and path in alert['syscheck']['path'] and alert['syscheck']['event'] == 'deleted':
                return True
    return False


# Check alerts when file is added or modify
def check_alert(path, fiels, event):
    with open(alerts_directory, 'r') as alerts:
        for line in alerts:
            alert = json.loads(line)
            result = True
            if 'syscheck' in alert and path in alert['syscheck']['path'] and alert['syscheck']['event'] == event:
                for f in fiels:
                    if f not in alert['syscheck']:
                        result = False
                if result == True:
                    return result
                        
    return False


# Main
if __name__ == "__main__":

    print (' ----- CHECK ADD FILES ALERTS --- ')
    for i in opt:
        for j in opt_check:
            path = '{0}/{1}/{2}/'.format(testing_dir, i, j)
            alert = '{0}_modify'.format(j)
            if check_alert(path, syscheck_fiels.get(alert),'added') == False:
                print(alert + ' alert does not exist for' + path)

    print('----- ----- ----- ----- Done')

    print (' ----- CHECK MODIFIED FILES ALERTS --- ')
    for i in opt:
        for j in opt_check:
            path = '{0}/{1}/{2}/'.format(testing_dir, i, j)
            alert = '{0}_modify'.format(j)
            if check_alert(path, syscheck_fiels.get(alert),'modified') == False:
                print(alert + ' alert does not exist for' + path)

    print('----- ----- ----- ----- Done')

    print(' ----- CHECK DELETE FILES ALERTS --- ')
    for i in opt:
        for j in opt_check:
            if check_delete('{0}/{1}/{2}'.format(testing_dir, i, j)) == False:
                print('Delete file alert does not exist for\n' + '{0}/{1}/{2}'.format(testing_dir, i, j))

    print('----- ----- ----- ----- Done')