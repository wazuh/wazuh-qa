# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from time import sleep

import pytest
import wazuh_testing.tools.agent_simulator as ag
import wazuh_testing.remote as remote
from wazuh_testing import UDP, TCP, TCP_UDP
from wazuh_testing.remote import check_push_shared_config
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import monitoring

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
        'disable_all_modules': True,
        'rcv_msg_limit': 1000
    },
    'debian9_4.4.0': {
        'manager_address': '127.0.0.1',
        'os': 'debian9',
        'version': 'v4.4.0',
        'disable_all_modules': True,
        'rcv_msg_limit': 1000
    },
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [x['PROTOCOL'] for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize("agent_name", agent_info.keys())
def test_agent_remote_configuration(agent_name, get_configuration, configure_environment, restart_remoted,
                                    create_agent_group):
    """ Check agents send its version, receives correctly shared configuration and that startup message
    is sent to the manager.

    Raises:
        AssertionError: if `wazuh-db` returns a wrong agent version, agents do not receive shared configuration or
        startup message after agent restart is not created
    """

    protocols = get_configuration['metadata']['protocol']

    for protocol in protocols.split(","):
        agent = ag.Agent(**agent_info[agent_name])
        agent.set_module_status('receive_messages', 'enabled')
        agent.set_module_status('keepalive', 'enabled')

        # Time necessary until socket creation
        sleep(1)

        sender = ag.Sender(agent_info[agent_name]['manager_address'], protocol=protocol)
        injector = ag.Injector(sender, agent)
        try:
            injector.run()

            agent.wait_status_active()

            # Uses [3:] substring to avoid #!- characters
            keep_alive_log = monitoring.make_callback(pattern=agent.keep_alive_raw_msg[3:],
                                                      prefix=monitoring.REMOTED_DETECTOR_PREFIX)

            wazuh_log_monitor.start(timeout=5, callback=keep_alive_log,
                                    error_message='The expected event has not been found in ossec.log')

            result = agent.get_agent_db_data('version')
            assert result == fr"Wazuh {agent_info[agent_name]['version']}"

            check_push_shared_config(protocol, agent, sender)

            injector.stop_receive()
            agent.set_module_status('keepalive', 'disabled')

            sender = ag.Sender(agent_info[agent_name]['manager_address'], protocol=protocol)
            agent.set_module_status('keepalive', 'enabled')
            injector = ag.Injector(sender, agent)
            injector.run()

            log_callback = remote.callback_start_up(agent.name)
            wazuh_log_monitor.start(timeout=15, callback=log_callback,
                                    error_message='The expected event has not been found in ossec.log')

        finally:
            injector.stop_receive()

