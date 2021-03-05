# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

import wazuh_testing.remote as remote
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.sockets import send_ar_message


# Marks
pytestmark = pytest.mark.tier(level=1)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'PROTOCOL': 'TCP', 'PORT': '1514'},
]
metadata = [
    {'protocol': 'TCP', 'port': '1514'}
]

configurations = load_wazuh_configurations(configurations_path, __name__ ,
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['PORT']}" for x in parameters]

manager_address = "localhost"

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param



def test_active_response_send(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` send correctly active response commands.

    Raises:
        AssertionError: if `wazuh-remoted` does not send correctly active response command.
    """

    protocol = get_configuration['metadata']['protocol']

    agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0", disable_all_modules= True)
    agent.set_module_status("receive_messages", "enabled")
    agent.set_module_status("keepalive", "enabled")

    time.sleep(1)

    sender = ag.Sender(manager_address, protocol=protocol)

    injector = ag.Injector(sender, agent)

    try:

        injector.run()
        time.sleep(20)

        send_ar_message(f"(local_source) [] NRN {agent.id} dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -")

        remote.check_agent_received_message(agent.rcv_msg_queue,"DEBUG: Received message: '#!-execd dummy-ar admin 1.1.1.1 1.1 44 (agente-cualquiera) any->/testing/testing.txt - -")

    finally:
        injector.stop_receive()

