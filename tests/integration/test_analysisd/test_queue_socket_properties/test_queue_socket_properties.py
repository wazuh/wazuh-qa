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

from wazuh_testing.tools import ANALYSISD_BINARY_PATH, ANALYSISD_QUEUE_SOCKET_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Variables
command_exec = f'{ANALYSISD_BINARY_PATH} -t'


@pytest.fixture(scope="function")
def socket_file_properties():
    """Get the inode and modification time values of the 'queue' socket of 'wazuh-analysisd'"""
    return os.stat(ANALYSISD_QUEUE_SOCKET_PATH).st_ino, os.path.getmtime(ANALYSISD_QUEUE_SOCKET_PATH)


@pytest.fixture(scope="function")
def run_analysisd_test_config():
    """Run the daemon configuration test mode of 'wazuh-analysisd'"""
    run = subprocess.Popen(['/bin/bash', '-c', command_exec])
    run.communicate()


before_socket_properties = socket_file_properties
after_socket_properties = socket_file_properties


# Tests
def test_queue_socket_properties(restart_analysisd, before_socket_properties, run_analysisd_test_config,
                                 after_socket_properties):
    '''
    description: Check if after running the configuration test of 'wazuh-analysisd' the properties
                 of the queue socket file are changed.

    wazuh_min_version: 4.3.0

    parameters:
        - restart_analysisd:
            type: fixture
            brief: Restart analysisd and truncate logs.
        - before_socket_properties:
            type: fixture
            brief: Obtain the previous properties of the 'queue' socket.
        - run_analysisd_test_config:
            type: fixture
            brief: Run the daemon configuration test mode of 'wazuh-analysisd'
        - after_socket_properties:
            type: fixture
            brief: Obtain the later properties of the 'queue' socket.

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
        - analysisd
    '''
    before_inode_file, before_status_time = before_socket_properties
    after_inode_file, after_status_time = after_socket_properties

    assert before_inode_file == after_inode_file, \
        f"The inode value for the socket  {ANALYSISD_QUEUE_SOCKET_PATH} has changed"

    assert before_status_time == after_status_time, \
        f"The modification time property value for the socket {ANALYSISD_QUEUE_SOCKET_PATH} has changed"
