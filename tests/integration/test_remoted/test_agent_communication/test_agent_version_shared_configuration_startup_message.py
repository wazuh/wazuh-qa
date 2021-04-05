# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from time import sleep

import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import UDP, TCP, TCP_UDP, remote
from wazuh_testing.remote import check_push_shared_config
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = pytest.mark.tier(level=2)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_version_shared_configuration_startup_message.yaml')
agent_conf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'agent.conf')

parameters = [
    {'PROTOCOL': TCP},
    {'PROTOCOL': UDP},
    {'PROTOCOL': TCP_UDP}
]

metadata = [
    {'protocol': TCP},
    {'protocol': UDP},
    {'protocol': TCP_UDP}
]

agent_info = {
    'debian7_420': {
        'manager_address': '127.0.0.1',
        'os': 'debian7',
        'version': 'v4.2.0',
        'disable_all_modules': True
    },
    'debian9_4.4.0': {
        'manager_address': '127.0.0.1',
        'os': 'debian9',
        'version': 'v4.4.0',
        'disable_all_modules': True
    }
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [x['PROTOCOL'] for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("agent_name", agent_info.keys())
def test_agent_remote_configuration(agent_name, get_configuration, configure_environment, remove_shared_files,
                                    restart_remoted, create_agent_group):
    """ Check agents send its version, receives correctly shared configuration and that startup message
    is sent to the manager.

    Raises:
        AssertionError: if `wazuh-db` returns a wrong agent version, agents do not receive shared configuration or
        startup message after agent restart is not created
    """

    protocols = get_configuration['metadata']['protocol']

    for protocol in protocols.split(","):
        agent = ag.Agent(**agent_info[agent_name])
        # Sleep to avoid ConnectionRefusedError
        sleep(1)
        sender = ag.Sender(agent_info[agent_name]['manager_address'], protocol=protocol)
        check_push_shared_config(agent, sender)
        wazuh_db_agent_version = agent.get_agent_version()
        assert wazuh_db_agent_version == fr"Wazuh {agent_info[agent_name]['version']}"
        log_callback = remote.callback_start_up(agent.name)
        wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
        wazuh_log_monitor.start(timeout=10, callback=log_callback,
                                error_message='The start up message has not been found in the logs')