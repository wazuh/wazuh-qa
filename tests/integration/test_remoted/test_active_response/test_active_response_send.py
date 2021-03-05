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



def connect(agent, protocol):
    sender = ag.Sender(manager_address, protocol=protocol)
    injector = ag.Injector(sender, agent)
    injector.run()
    agent.wait_status_active()
    return agent, sender, injector


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

    cfg = get_configuration['metadata']

    agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0")

    a, sender, injector = connect(agent, cfg['protocol'])
    time.sleep(20)

    send_ar_message(b'(local_source) [] NRN 001 restart-wazuh0 admin 1.1.1.1 1.1 44 (agente-cualquiera) any->/carpeta/testing - -')

    log_callback = remote.callback_active_response_received()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = remote.callback_active_response_sent()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")






"""
agent message

2021/03/05 09:01:42 ossec-agentd[71402] receiver.c:92 at receive_msg(): DEBUG: Received message: '#!-execd restart-wazuh0 admin 1.1.1.1 1.1 44 (agente-cualquiera) any->/carpeta/testing - -


"""