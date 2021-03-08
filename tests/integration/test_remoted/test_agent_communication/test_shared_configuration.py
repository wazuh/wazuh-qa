# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import os
import subprocess

import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import remote as rd
from time import sleep
from wazuh_testing import UDP, TCP, TCP_UDP
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_shared_configuration.yaml')
agent_conf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'agent.conf')

parameters = [
    {'PROTOCOL': TCP},
    {'PROTOCOL': UDP},
    {'PROTOCOL': TCP_UDP},
]

metadata = [
    {'protocol': TCP},
    {'protocol': UDP},
    {'protocol': TCP_UDP},
]

agent_info = {
    'manager_address': '127.0.0.1',
    'os': 'debian7',
    'version': '4.2.0',
    'disable_all_modules': True
}

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
config_ids = [x['PROTOCOL'] for x in parameters]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def check_push_shared_config(protocol):
    """Allow to check if the manager sends the shared configuration to agents through remoted

    First, check if the default group configuration file is completely pushed (up message, configuration
    and close message). Then add the agent to a new group and check if the new configuration is pushed.
    Also it checks that the same config isn't pushed two times.

    Args:
        protocol (str): It can be UDP or TCP.

    Raises:
        TimeoutError: If agent does not receive the manager ACK message in the expected time.
    """

    # Create agent and sender object with default parameters
    agent = ag.Agent(**agent_info)

    # Sleep to avoid ConnectionRefusedError
    sleep(1)

    sender = ag.Sender(agent_info['manager_address'], protocol=protocol)

    # Activate receives_messages modules in simulated agent.
    agent.set_module_status('receive_messages', 'enabled')

    # Run injector with only receive messages module enabled
    injector = ag.Injector(sender, agent)
    try:
        injector.run()

        # Wait until remoted has loaded the new agent key
        rd.wait_to_remoted_key_update(wazuh_log_monitor)

        # Send the start-up message
        sender.send_event(agent.startup_msg)
        sender.send_event(agent.keep_alive_event)

        # Check up file (push start) message
        rd.check_agent_received_message(agent.rcv_msg_queue, r'#!-up file \w+ merged.mg', timeout=10,
                                        error_message="initial up file message not received")

        # Check agent.conf message
        rd.check_agent_received_message(agent.rcv_msg_queue, '#default', timeout=10,
                                        error_message="agent.conf message not received")
        # Check close file (push end) message
        rd.check_agent_received_message(agent.rcv_msg_queue, 'close', timeout=10,
                                        error_message="initial close message not received")

        sender.send_event(agent.keep_alive_event)

        # Check that push message doesn't appear again
        with pytest.raises(TimeoutError):
            rd.check_agent_received_message(agent.rcv_msg_queue, r'#!-up file \w+ merged.mg', timeout=5)

        # Add agent to group and check if the configuration is pushed.
        subprocess.run(["/var/ossec/bin/agent_groups", "-q", "-a", "-i", agent.id, "-g", "testing_group"])
        sender.send_event(agent.keep_alive_event)
        rd.check_agent_received_message(agent.rcv_msg_queue, '#!-up file .* merged.mg', timeout=10,
                                        error_message="New group shared config not received")

    finally:
        injector.stop_receive()


def test_push_shared_config(get_configuration, configure_environment, restart_remoted, create_agent_group):
    """ Checks that manager push shared configuration to agents when required.

    Checks if Wazuh Manager sends new shared files from group shared folder when the merged.mg checksum received from
    agent is different than the stored one, for example, when the group configuration changes.
    """

    protocols = get_configuration['metadata']['protocol']

    for protocol in protocols.split(","):
        check_push_shared_config(protocol)

