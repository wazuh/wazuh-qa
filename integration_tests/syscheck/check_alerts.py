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
    'check_mtime', 'check_inode','report_changes', 'tags']


# Syscheck alert fields when add file
add_fiels = {}
add_fiels['check_all'] = ['path', 'size_after', 'perm_after', 'uid_after', 'gid_after', 'md5_after', 'sha1_after', 'sha256_after', 'uname_after', 'gname_after', \
    'mtime_after', 'inode_after', 'event'] # check_all
add_fiels['check_sum'] = ['path', 'md5_after', 'sha1_after', 'sha256_after', 'event'] # check_sum
add_fiels['check_md5sum'] = ['path', 'md5_after', 'event'] # check_md5sum
add_fiels['check_sha1sum'] = ['path', 'sha1_after', 'event'] # check_sha1sum 
add_fiels['check_sha256sum'] = ['path', 'sha256_after', 'event'] # check_sha256sum
add_fiels['check_size'] = ['path', 'event', 'size_after'] # check_size
add_fiels['check_owner'] = ['path', 'event', 'uid_after','uname_after'] # check_ownwer
add_fiels['check_group'] = ['path', 'event', 'gid_after','gname_after'] # check_group
add_fiels['check_perm'] = ['path', 'event', 'perm_after'] # check_perf
add_fiels['check_mtime'] = ['path', 'event', 'mtime_after'] # check_mtime
add_fiels['check_inode'] = ['path', 'event', 'inode_after'] # check_inode
add_fiels['report_changes'] = ['path', 'event', 'size_after'] # check_size
add_fiels['tags'] = ['path', 'event', 'size_after'] # check_size

# Syscheck alert fields when modify inode file
modInode_fiels = {}
modInode_fiels['check_inode'] = ['path', 'event', 'inode_after', 'inode_before']

# Syscheck alert fields when modify file
modFile_fiels = {}
modFile_fiels['check_all'] = ['path', 'event', 'inode_after', 'size_before', 'size_after', 'perm_after', 'uid_after', 'gid_after', 'md5_before', 'md5_after', 'sha1_before', \
    'sha1_after', 'sha256_before', 'sha256_after', 'uname_after', 'gname_after', 'mtime_before', 'mtime_after'] # check_all - modify file
modFile_fiels['check_sum'] = ['path', 'event', 'md5_before', 'md5_after', 'sha1_before', 'sha1_after', 'sha256_before', 'sha256_after'] # check_sum -modifiy file
modFile_fiels['check_md5sum'] = ['path', 'event', 'md5_before', 'md5_after'] # check_md5sum - modify_file
modFile_fiels['check_sha1sum'] = ['path', 'event', 'sha1_before', 'sha1_after'] # check_sha1sum - modify file
modFile_fiels['check_sha256sum'] = ['path', 'event', 'sha256_before', 'sha256_after'] # check_sha256 - modify file
modFile_fiels['check_size'] = ['path', 'event', 'size_before', 'size_after'] # check_size - modify file
modFile_fiels['check_mtime'] = ['path', 'event', 'mtime_after', 'mtime_before'] # check_mtime - modify file
modFile_fiels['report_changes'] = ['path', 'event', 'size_before', 'size_after', 'diff'] # check_size
modFile_fiels['tags'] = ['path', 'event', 'size_before', 'size_after', 'tags'] # check_size

# Syscheck alert fields when chagne owner file
modOwner_fiels = {}
modOwner_fiels['check_all'] = ['path', 'size_after', 'perm_after', 'uid_before', 'uid_after', 'uname_before', 'uname_after', 'gid_after', 'md5_after', 'sha1_after', 'sha256_after', 'uname_after', 'gname_after', \
    'mtime_after', 'inode_after', 'event'] # check_all
modOwner_fiels['check_owner'] = ['path', 'event', 'uid_before', 'uid_after', 'uname_before', 'uname_after'] # check_owner

# Syscheck alert fields when change group file
modGroup_fiels = {}
modGroup_fiels['check_all'] = ['path', 'size_after', 'perm_after', 'uid_after', 'gid_after', 'md5_after', 'sha1_after', 'sha256_after', 'uname_after', 'gname_after', \
    'mtime_after', 'inode_after', 'event'] # check_all
modGroup_fiels['check_group'] = ['path', 'event', 'gid_before', 'gid_after', 'gname_before', 'gname_after'] # check_group

# Syscheck alert fields when change perm file
modPerm_fiels = {}
modPerm_fiels['check_perm'] = ['path', 'perm_before', 'perm_after', 'event']


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
                        break
                if result == True:
                    return result
                        
    return False


# Test
def test_alerts(dic, event):
    print (' ----- CHECK FILES ALERTS --- {0}'.format(event))
    for i in opt:
        for j in opt_check:
            path = '{0}/{1}/{2}/'.format(testing_dir, i, j)
            if dic.get(j) != None:
                if check_alert(path, dic.get(j), event) == False:
                    print('\nNo exist {0} alert for: \nOption: '.format(event) + j + '\nPath: ' + path)

    print('----- ----- ----- ----- Done')


# Main
if __name__ == "__main__":
 
    test_alerts(add_fiels, 'added')
    test_alerts(modInode_fiels, 'modified')
    test_alerts(modFile_fiels, 'modified')
    test_alerts(modOwner_fiels, 'modified')
    test_alerts(modGroup_fiels, 'modified')
    test_alerts(modPerm_fiels, 'modified')

    print(' ----- CHECK DELETE FILES ALERTS --- ')
    for i in opt:
        for j in opt_check:
            path = '{0}/{1}/{2}/'.format(testing_dir, i, j)
            if check_delete(path) == False:
                print('\nNo exist removed alert for: \nOption: ' + j + '\nPath: ' + path)

    print('----- ----- ----- ----- Done')