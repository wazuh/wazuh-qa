'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Active responses perform various countermeasures to address active
       threats, such as blocking access to an agent from the threat source when certain
       criteria are met. These tests will check if an active response command is sent
       correctly to the Wazuh agent by `wazuh-remoted` daemon.

tier: 0

modules:
    - wazuh_db

components:
    - manager

daemons:
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''

import os
import pytest
import subprocess
import time
import numbers

from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import recursive_directory_creation, remove_file, truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH


# Marks
pytestmark = pytest.mark.tier(level=0)


# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_db_backups_conf.yaml')
backups_path = os.path.join(WAZUH_PATH, 'backup', 'db')
interval = 5
parameters = [{'ENABLED': 'yes', 'INTERVAL': str(interval)+'s', 'MAX_FILES':''},
              {'ENABLED': 'yes', 'INTERVAL': str(interval)+'s', 'MAX_FILES':'value'},
              {'ENABLED': 'yes', 'INTERVAL': '', 'MAX_FILES':'1'},
              {'ENABLED': 'yes', 'INTERVAL': 'value', 'MAX_FILES':1},
              {'ENABLED': 'no', 'INTERVAL': str(interval)+'s', 'MAX_FILES':1},
              {'ENABLED': 'yes', 'INTERVAL': str(interval)+'s', 'MAX_FILES':1},
]
metadata = [{'ENABLED': 'yes', 'INTERVAL': str(interval)+'s', 'MAX_FILES':''},
            {'ENABLED': 'yes', 'INTERVAL': str(interval)+'s', 'MAX_FILES':'value'},
            {'ENABLED': 'yes', 'INTERVAL': '', 'MAX_FILES':1},
            {'ENABLED': 'yes', 'INTERVAL': 'value', 'MAX_FILES':1},
            {'ENABLED': 'no', 'INTERVAL': str(interval)+'s', 'MAX_FILES':1},
            {'ENABLED': 'yes', 'INTERVAL': str(interval)+'s', 'MAX_FILES':1},
]

configurations = load_wazuh_configurations(configurations_path, __name__ ,
                                           params=parameters, metadata=metadata)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


def restart_wazuh(log_monitor):
    # Stop Wazuh
    control_service('stop')
    
    # Reset ossec.log and start a new monitor
    #truncate_file(LOG_FILE_PATH)
    #log_monitor = FileMonitor(LOG_FILE_PATH)
    
    # Start Wazuh
    control_service('start')

def validate_interval_format(interval):
    if interval=='':
        return False
    if interval[-1] not in ['s','m', 'h','d','w','y'] or not isinstance(int(interval[0:-1]), numbers.Number):
        return False
    return True

# Fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def remove_backups(request):
    "Creates backups folder in case it does not exist."
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)
    yield
    remove_file(backups_path)


# Tests
def test_wdb_backup_configs(get_configuration, configure_environment, remove_backups):
    '''
    description: 
  
    '''
    test_interval = get_configuration['metadata']['INTERVAL']
    test_max_files = get_configuration['metadata']['MAX_FILES']
    try:
        restart_wazuh(wazuh_log_monitor)
    except (subprocess.CalledProcessError, ValueError) as err:
        if not validate_interval_format(test_interval):
            wazuh_log_monitor.start(callback=generate_monitoring_callback(r".*Invalid value for element ('interval':.*)"), timeout=15,
                                           error_message='Did not receive expected '
                                                         '"Invalid value element for interval..." event')
            return
        elif not isinstance(test_max_files, numbers.Number):
            wazuh_log_monitor.start(callback=generate_monitoring_callback(r".*Invalid value for element ('max_files':.*)"), timeout=15,
                                           error_message='Did not receive expected '
                                                         '"Invalid value element for max_files..." event')
            return
        else:
            pytest.fail(f"Got unexpected Error - {err}")

    # Wait for backup files to be generated
    time.sleep(interval*(int(test_max_files)+1))
    
    # Manage if backup generation is not enabled - no backups expected
    if get_configuration['metadata']['ENABLED'] == 'no':
        # Fail the test if a file or more were found in the backups_path
        if os.listdir(backups_path):
            pytest.fail("Error - A file was found in backups_path and No backups where expected - enabled = no")
    # Manage if backup generation is enabled - one or more backups expected
    else:
        result= wazuh_log_monitor.start(timeout=15, accum_results=test_max_files+1,
                                callback=generate_monitoring_callback(r'.*Created Global database backup "(backup/db/global.db-backup.*.gz)"'),
                                error_message='Did not receive expected "Created Global database backup..." event').result()
        print(result)
        for file in os.listdir(backups_path):
            print(os.path.join(backups_path, file))
