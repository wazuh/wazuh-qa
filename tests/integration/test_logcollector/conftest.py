# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.manager_keys import sslmanager_key, sslmanager_cert

from time import sleep

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
    """
    authd_remoted_simulator_configuration = get_connection_configuration

    # Write custom manager keys and certs in specified paths

    with open(authd_remoted_simulator_configuration['server_keys'], "w") as key:
        key.write(sslmanager_key)
    with open(authd_remoted_simulator_configuration['server_cert'], "w") as cert:
        cert.write(sslmanager_cert)

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
