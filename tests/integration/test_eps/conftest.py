# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import subprocess
import socket
import shutil
import pytest

from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import configuration, SIMULATE_AGENT, ARCHIVES_LOG_FILE_PATH, ALERT_LOGS_PATH, ALERT_FILE_PATH, ALERT_PATH
from wazuh_testing.tools.file import delete_file


@pytest.fixture(scope='function')
def restart_analysisd_function():
    """Restart wazuh-analysisd daemon before starting a test, and stop it after finishing"""
    control_service('restart', daemon='wazuh-analysisd')
    yield
    control_service('stop', daemon='wazuh-analysisd')


@pytest.fixture(scope='session')
def configure_local_internal_options_eps(request):
    """Fixture to configure the local internal options file."""
    # Define local internal options for vulnerability detector tests
    local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0', 'analysisd.state_interval': f"{request.param[0]}"}

    # Backup the old local internal options
    backup_local_internal_options = configuration.get_wazuh_local_internal_options()

    # Set the new local internal options configuration
    configuration.set_wazuh_local_internal_options(configuration.create_local_internal_options(local_internal_options))

    yield

    # Backup the old local internal options cofiguration
    configuration.set_wazuh_local_internal_options(backup_local_internal_options)


@pytest.fixture(scope='function')
def set_wazuh_configuration_eps(configuration, set_wazuh_configuration, configure_local_internal_options_eps):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
        configure_local_internal_options_eps (fixture): Set the local_internal_options.conf file.
    """
    yield


@pytest.fixture(scope='function')
def simulate_agent(request):
    """Fixture to execute the script simulate_agent.py"""
    #Get IP address of the host
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)

    file_excecute = os.path.abspath(SIMULATE_AGENT)
    subprocess.call(f"python3 {file_excecute} -a {IPAddr} -n {request.param['num_agent']} -m \
                    {request.param['modules']} -s {request.param['events_per_sec']} -t {request.param['time']}", \
                    shell=True)

    yield


def delete_folder_content(folder):
    """Delete alerts folder content execution"""
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        try:
            shutil.rmtree(filepath)
        except OSError:
            os.remove(filepath)


@pytest.fixture(scope='function')
def delete_alerts_folder():
    """Delete alerts folder content before and after execution"""

    delete_folder_content(ALERT_PATH)

    yield

    delete_folder_content(ALERT_PATH)


# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import subprocess
import socket
import shutil
from typing import List
import pytest

from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import configuration, SIMULATE_AGENT, ARCHIVES_LOG_FILE_PATH, ALERT_LOGS_PATH, ALERT_FILE_PATH, ALERT_PATH, WAZUH_INTERNAL_OPTIONS
from wazuh_testing.fim import change_internal_options


@pytest.fixture(scope='function')
def restart_analysisd_function():
    """Restart wazuh-analysisd daemon before starting a test, and stop it after finishing"""
    control_service('restart', daemon='wazuh-analysisd')
    yield
    control_service('stop', daemon='wazuh-analysisd')


@pytest.fixture(scope='session')
def configure_local_internal_options_eps(request):
    """Fixture to configure the local internal options file."""
    # Define local internal options for vulnerability detector tests
    local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0',\
                              'analysisd.state_interval': f"{request.param[0]}"}

    # Backup the old local internal options
    backup_local_internal_options = configuration.get_wazuh_local_internal_options()

    # Set the new local internal options configuration
    configuration.set_wazuh_local_internal_options(configuration.create_local_internal_options(local_internal_options))

    yield

    # Backup the old local internal options cofiguration
    configuration.set_wazuh_local_internal_options(backup_local_internal_options)


@pytest.fixture(scope='function')
def set_wazuh_configuration_eps(configuration, set_wazuh_configuration, configure_local_internal_options_eps):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
        configure_local_internal_options_eps (fixture): Set the local_internal_options.conf file.
    """
    yield


@pytest.fixture(scope='function')
def simulate_agent(request):
    """Fixture to execute the script simulate_agent.py"""
    #Get IP address of the host
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)

    file_excecute = os.path.abspath(SIMULATE_AGENT)
    subprocess.call(f"python3 {file_excecute} -a {IPAddr} -n {request.param['num_agent']} -m \
                    {request.param['modules']} -s {request.param['events_per_sec']} -t {request.param['time']}", \
                    shell=True)

    yield


def delete_folder_content(folder):
    """Delete alerts folder content execution"""
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        try:
            shutil.rmtree(filepath)
        except OSError:
            os.remove(filepath)


@pytest.fixture(scope='function')
def delete_alerts_folder():
    """Delete alerts folder content before and after execution"""

    delete_folder_content(ALERT_PATH)

    yield

    delete_folder_content(ALERT_PATH)


def get_wazuh_internal_options() -> List[str]:
    """Get current `internal_options.conf` file content.

    Returns
        List of str: A list containing all the lines of the `ossec.conf` file.
    """
    with open(WAZUH_INTERNAL_OPTIONS) as f:
        lines = f.readlines()
    return lines


def set_wazuh_internal_options(wazuh_local_internal_options: List[str]):
    """Set up Wazuh `local_internal_options.conf` file content.

    Returns
        List of str: A list containing all the lines of the `local_interal_options.conf` file.
    """
    with open(WAZUH_INTERNAL_OPTIONS, 'w') as f:
        f.writelines(wazuh_local_internal_options)


@pytest.fixture(scope='session')
def configure_internal_options_eps():
    """Fixture to configure the internal options file."""

    # Backup the old local internal options
    backup_internal_options = get_wazuh_internal_options()

    change_internal_options('analysisd.event_threads', '1')
    change_internal_options('analysisd.syscheck_threads', '1')
    change_internal_options('analysisd.syscollector_threads', '1')
    change_internal_options('analysisd.rootcheck_threads', '1')
    change_internal_options('analysisd.sca_threads', '1')
    change_internal_options('analysisd.hostinfo_threads', '1')
    change_internal_options('analysisd.winevt_threads', '1')
    change_internal_options('analysisd.rule_matching_threads', '1')
    change_internal_options('analysisd.dbsync_threads', '1')
    change_internal_options('remoted.worker_pool', '1')

    yield

    # Backup the old local internal options cofiguration
    set_wazuh_internal_options(backup_internal_options)
