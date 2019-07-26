#!/usr/bin/python
# Testing FIM options work. Part II
# Checks that alerts generate in part I are correct.


import json, yaml
import os, sys


# Directories and options
alerts_directory = '/var/ossec/logs/alerts/alerts.json'
testing_dir_linux = '/home/lopezziur/testing_fim_options'
testing_dir_windows = 'c:\\users\\administrator\\documents\\testing_fim_options'
opt = ['t_frequency', 't_whodata', 't_realtime']


# Check alerts:
def check_delete(path):
    with open(alerts_directory, 'r') as alerts:
        for line in alerts:
            alert = json.loads(line)
            if 'syscheck' in alert and path in alert['syscheck']['path'] and alert['syscheck']['event'] == 'deleted':
                return True
    alerts.close()
    return False

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
    alerts.close()
    return False

def check_no_alert(path):
    print ('\n  ----- CHECK --- no alert for:\n{0}'.format(path))
    result = True
    with open(alerts_directory, 'r') as alerts:
        for line in alerts:
            alert = json.loads(line)
            if 'syscheck' in alert and path in alert['syscheck']['path']:
                print('\nERROR --- Exist alert for: {0}'.format(path))
                result = False
    alerts.close()
    return result


# Test
def test_alerts(dic, event, so, opt_check):
    for i in opt:
        for j in opt_check:
            if so == 'linux':
                path = '{0}/{1}/{2}/'.format(testing_dir_linux, i, j)
            else:
                path = '{0}\\{1}\\{2}\\'.format(testing_dir_windows, i, j)
            if dic.get(j) != None:
                if check_alert(path, dic.get(j), event) == False:
                    print('\nNo exist {0} alert for: \nOption: '.format(event) + j + '\nPath: ' + path)



####
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print('windows or linux')

    else:

        so = sys.argv[1]
        if so == 'linux':
            directory = testing_dir_linux
            opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner', \
                'check_group', 'check_perm', 'check_mtime', 'check_inode','report_changes', 'tags']
        else:
            directory = testing_dir_windows
            opt_check = ['check_all', 'check_sum', 'check_sha1sum', 'check_md5sum', 'check_sha256sum', 'check_size', 'check_owner', \
                'check_perm', 'check_attrs', 'check_mtime','report_changes', 'tags']

        with open('syscheck.yml') as syscheck:
            data = yaml.safe_load(syscheck)
            if so == 'linux':
                print ('\n  ----- CHECK FILES ALERTS --- Add')
                test_alerts(data['linux']['add'], 'added', so, opt_check)
                print('  ----- ----- ----- ----- ----- ----- ')
                print ('\n  ----- CHECK FILES ALERTS --- Modify file')
                test_alerts(data[so]['modify'], 'modified', so, opt_check)
                test_alerts(data[so]['modify-inode'], 'modified', so, opt_check)
                test_alerts(data[so]['change-owner'], 'modified', so, opt_check)
                test_alerts(data[so]['change-group'], 'modified', so, opt_check)
                test_alerts(data[so]['change-perm'], 'modified', so, opt_check)
                print('  ----- ----- ----- ----- ----- -----')
            elif so == 'windows':
                print ('\n  ----- CHECK --- Add alerts')
                test_alerts(data[so]['add'], 'added', so, opt_check)
                print('  ----- ----- ----- ----- ----- ----- ')
                print ('\n  ----- CHECK --- Modify file alerts')
                test_alerts(data[so]['modify'], 'modified', so, opt_check)
                print ('\n  ----- CHECK --- Modify owner alerts')
                test_alerts(data[so]['change-owner'], 'modified', so, opt_check)
                print ('\n  ----- CHECK --- Modify attributes alerts')
                test_alerts(data[so]['change-attr'], 'modified', so, opt_check)
                print('  ----- ----- ----- ----- ----- -----')
        syscheck.close()

        
        for i in opt:
            check_no_alert('{0}/{1}/restrict'.format(directory, i))
            check_no_alert('{0}/{1}/recursion_level/level1/level2'.format(directory, i))

        print('\n  ----- CHECK --- Delete alerts')
        for i in opt:
            for j in opt_check:
                path = '{0}\\{1}\\{2}\\'.format(directory, i, j)
                if check_delete(path) == False:
                    print('\nNo exist removed alert for: \nOption: ' + j + '\nPath: ' + path)

        print('  ----- ----- ----- ----- ----- ----- ')
