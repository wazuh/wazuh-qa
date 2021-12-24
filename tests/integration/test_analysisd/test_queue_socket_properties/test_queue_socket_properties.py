'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon refreshes the queue socket file every time the daemon is set to
       the testing configuration.
       Specifically, this test will check if after setting up the 'wazuh-analysisd' daemon to the 
       testing configuration the Inode and Filetime properties of the queue socket are changed.

tier: 0

modules:
    - analysisd

components:
    - manager

daemons:
    - wazuh-analysisd

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - analysisd
'''
import os
import pytest
import subprocess

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# variables

ANALYSISD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue')
analysisd_path =  os.path.join(WAZUH_PATH,'bin', 'wazuh-analysisd')
command_exec = f'{analysisd_path} -t'

# Fixtures

@pytest.fixture(scope="function")
def socket_file_properties():
    """Get the Inode and File time value of the 'queue' socket of 'wazuh-analysisd'"""
    return os.stat(ANALYSISD_SOCKET).st_ino, os.path.getmtime(ANALYSISD_SOCKET)

@pytest.fixture(scope="function")
def run_analysisd_test_config():
    """Run the test configuration mode for the 'wazuh-analysisd' daemon"""
     # restart analysisd daemon
    control_service('restart', daemon='wazuh-analysisd')
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    # run analysisd test configuration mode
    run = subprocess.Popen(['/bin/bash', '-c', command_exec])
    run.communicate()
    

def test_queue_socket_properties(socket_file_properties, run_analysisd_test_config):
    '''
    description: Check if when the 'wazuh-analysisd' daemon is set up to the testing configuration, the Inode value
                 and the File time value of the 'queue' socket are modified.

    wazuh_min_version: 4.2.0

    parameters:
        - socket_file_properties:
            type: fixture
            brief: Obtain the current properties of the 'queue' socket.
        - run_analysisd_test_config:
            type: fixture
            brief: Change the wazuh-analysisd daemon configuration into the testing configuration mode.
        

    assertions:
        - Verify that the Inode value of the socket file does not change its value after analysisd gets the
          testing configuration set up.
        - Verify that the File time value of the socket file does not change its value after analysisd
          gets the testing configuration set up.
    
    input_description: The test gets the current properties of the socket file and some configutation parameters
                       to configure the 'wazuh-analysisd' daemon.

    expected_output:
        - f"The Inode value for the socket  {ANALYSISD_SOCKET} has changed"
        - f"The Filetime value for the socket {ANALYSISD_SOCKET} has changed"
    tags:
        - errors
    '''
    # Check if analysisd daemon is running 
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    current_inode_file, current_status_time = socket_file_properties

    run_analysisd_test_config

    assert current_inode_file == os.stat(ANALYSISD_SOCKET).st_ino, \
            f"The Inode value for the socket  {ANALYSISD_SOCKET} has changed"

    assert current_status_time == os.path.getmtime(ANALYSISD_SOCKET), \
            f"The File time value for the socket {ANALYSISD_SOCKET} has changed"
