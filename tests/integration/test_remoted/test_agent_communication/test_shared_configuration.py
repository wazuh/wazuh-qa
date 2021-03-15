# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from time import sleep

import pytest
import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import UDP, TCP, TCP_UDP
from wazuh_testing.remote import check_push_shared_config
from wazuh_testing.tools.configuration import load_wazuh_configurations

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


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=config_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_push_shared_config(get_configuration, configure_environment, restart_remoted, create_agent_group):
    """ Checks that manager push shared configuration to agents when required.

    Checks if Wazuh Manager sends new shared files from group shared folder when the merged.mg checksum received from
    agent is different than the stored one, for example, when the group configuration changes.
    """

    protocols = get_configuration['metadata']['protocol']

    for protocol in protocols.split(","):
        agent = ag.Agent(**agent_info)
        # Sleep to avoid ConnectionRefusedError
        sleep(1)
        sender = ag.Sender(agent_info['manager_address'], protocol=protocol)
        check_push_shared_config(agent, sender)
