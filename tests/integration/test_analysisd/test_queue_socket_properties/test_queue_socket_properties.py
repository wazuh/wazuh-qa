'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon refreshes the queue socket file every time the configuration test is executed
       Specifically, this test will check if after running the configuration test of 'wazuh-analysisd' the properties
       of the queue socket file are changed.

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

from wazuh_testing.tools import WAZUH_PATH, ANALYSISD_QUEUE_SOCKET_PATH, ANALYSISD_DAEMON
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Variables

analysisd_path = os.path.join(WAZUH_PATH, 'bin', ANALYSISD_DAEMON)
command_exec = f'{analysisd_path} -t'

# Fixtures


@pytest.fixture(scope="function")
def socket_file_properties():
    """Get the inode and modification time values of the 'queue' socket of 'wazuh-analysisd'"""
    return os.stat(ANALYSISD_QUEUE_SOCKET_PATH).st_ino, os.path.getmtime(ANALYSISD_QUEUE_SOCKET_PATH)


@pytest.fixture(scope="function")
def run_analysisd_test_config():
    """Run the daemon configuration test mode of 'wazuh-analysisd'"""
    # restart analysisd daemon
    control_service('restart', daemon='wazuh-analysisd')
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    # run analysisd test configuration mode
    run = subprocess.Popen(['/bin/bash', '-c', command_exec])
    run.communicate()


def test_queue_socket_properties(socket_file_properties, run_analysisd_test_config):
    '''
    description: check if after running the configuration test of 'wazuh-analysisd' the properties
                 of the queue socket file are changed.

    wazuh_min_version: 4.2.0

    parameters:
        - socket_file_properties:
            type: fixture
            brief: Obtain the current properties of the 'queue' socket.
        - run_analysisd_test_config:
            type: fixture
            brief: Run the daemon configuration test mode of 'wazuh-analysisd'


    assertions:
        - Verify that the Inode value of the socket file does not change its value after running the
          configuration test of 'wazuh-analysisd'
        - Verify that the File time value of the socket file does not change its value after running the
          configuration test of 'wazuh-analysisd'

    input_description: The test gets the current properties of the socket file and some parameters
                       to run the daemon configuration test of 'wazuh-analysisd'.

    expected_output:
        - f"The inode value for the socket  {ANALYSISD_QUEUE_SOCKET_PATH} has changed"
        - f"The modification time property for the socket {ANALYSISD_QUEUE_SOCKET_PATH} has changed"
    tags:
        - errors
    '''
    # Check if analysisd daemon is running
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    current_inode_file, current_status_time = socket_file_properties

    run_analysisd_test_config

    assert current_inode_file == os.stat(ANALYSISD_QUEUE_SOCKET_PATH).st_ino, \
        f"The inode value for the socket  {ANALYSISD_QUEUE_SOCKET_PATH} has changed"

    assert current_status_time == os.path.getmtime(ANALYSISD_QUEUE_SOCKET_PATH), \
        f"The modification time property value for the socket {ANALYSISD_QUEUE_SOCKET_PATH} has changed"
