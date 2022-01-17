# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest
from shutil import copyfile
import sys

if sys.platform != 'win32':
    from wazuh_testing.tools import LOGCOLLECTOR_FILE_STATUS_PATH

from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
import wazuh_testing.tools.configuration as conf
from wazuh_testing.logcollector import LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools import CLIENT_CUSTOM_KEYS_PATH, CLIENT_CUSTOM_CERT_PATH, get_service
from os.path import exists
from os import remove

DAEMON_NAME = "wazuh-logcollector"


@pytest.fixture(scope='module')
def restart_logcollector(get_configuration, request):
    """Reset log file and start a new monitor."""
    control_service('stop', daemon=DAEMON_NAME)
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon=DAEMON_NAME)


@pytest.fixture(scope='module')
def init_authd_remote_simulator(get_connection_configuration, request):
    """Initialize authd and remoted simulator

    Args:
        get_connection_configuration (fixture): Dictionary with authd and remoted parameters.
        request (fixture): Provide information on the executing test function.
    """
    authd_remoted_simulator_configuration = get_connection_configuration

    # Write custom manager keys and certs in specified paths

    copyfile(CLIENT_CUSTOM_KEYS_PATH, authd_remoted_simulator_configuration['server_keys'])
    copyfile(CLIENT_CUSTOM_CERT_PATH, authd_remoted_simulator_configuration['server_cert'])

    authd_simulator = AuthdSimulator(authd_remoted_simulator_configuration['ip_address'],
                                     enrollment_port=authd_remoted_simulator_configuration['authd_port'],
                                     key_path=authd_remoted_simulator_configuration['server_keys'],
                                     cert_path=authd_remoted_simulator_configuration['server_cert'])
    authd_simulator.start()

    remoted_simulator = RemotedSimulator(server_address=authd_remoted_simulator_configuration['ip_address'],
                                         remoted_port=authd_remoted_simulator_configuration['remoted_port'],
                                         protocol=authd_remoted_simulator_configuration['protocol'],
                                         mode=authd_remoted_simulator_configuration['remoted_mode'],
                                         start_on_init=True,
                                         client_keys=authd_remoted_simulator_configuration['client_keys'])

    setattr(request.module, 'remoted_simulator', remoted_simulator)
    setattr(request.module, 'authd_simulator', authd_simulator)

    truncate_file(authd_remoted_simulator_configuration['client_keys'])

    control_service('restart')

    yield

    remoted_simulator.stop()
    authd_simulator.shutdown()


@pytest.fixture(scope='function')
def delete_file_status_json():
    """Delete file_status.json from logcollector"""
    remove(LOGCOLLECTOR_FILE_STATUS_PATH) if exists(LOGCOLLECTOR_FILE_STATUS_PATH) else None

    yield


@pytest.fixture(scope='function')
def truncate_log_file():
    """Truncate the log file (ossec.log)"""
    truncate_file(LOG_FILE_PATH)

    yield


@pytest.fixture(scope='module')
def restart_monitord():
    wazuh_component = get_service()

    """Reset log file and start a new monitor."""
    if wazuh_component == 'wazuh-manager':
        control_service('restart', daemon='wazuh-monitord')
    else:
        control_service('restart', daemon='wazuh-agentd')