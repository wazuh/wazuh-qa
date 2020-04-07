# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import json
import socket

from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor, SocketController

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

project_id = 'sinuous-voice-271711'
subscription_name = 'wazuh-integration'
credentials_file = '/var/ossec/credentials.json'
enabled = 'yes'
pull_on_start = 'yes'
max_messages = 200
interval = '2h'
logging = "debug"
day = 9
wday = 'tuesday'
time = '08:00'
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
component = "wmodules"
configuration = "wmodules"
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_remote_conf.yaml')

# configurations

monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': project_id, 'SUBSCRIPTION_NAME': subscription_name,
               'CREDENTIALS_FILE': credentials_file, 'ENABLED': enabled,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'INTERVAL': interval, 'LOGGING': logging, 'DAY': day, 'WDAY': wday,
               'TIME': time, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
def gcp_remote_configuration(component_name, config):
    socket_path = os.path.join(WAZUH_PATH, 'queue', 'ossec')
    dest_socket = os.path.join(socket_path, component_name)
    command = f"getconfig {config}"

    # Socket connection
    s = SocketController(dest_socket)

    try:
        # Send message
        s.send(command.encode(), True)

        # Receive response
        rec_msg_ok, rec_msg = s.receive(True).decode().split(" ", 1)
    except socket.timeout as error:
        s.close()
        raise TimeoutError(error)

    try:
        if rec_msg_ok.startswith('ok'):
            remote_configuration = json.loads(rec_msg)
            remote_configuration_gcp = remote_configuration['wmodules'][6]['gcp-pubsub']
        else:
            s.close()
            raise ValueError(rec_msg_ok)
    except UnboundLocalError as error:
        s.close()
        raise TimeoutError(error)
    return remote_configuration_gcp


def test_remote_configuration(get_configuration, configure_environment,
                              restart_wazuh, wait_for_gcp_start):
    """
    These tests verify remote configuration matches with the ossec_configuration.
    The first test checks the default options. The second checks the configuration when it is completed.
    The last one checks repeated options in ossec.conf, so the last value will be applied.
    """
    tags_to_apply = get_configuration['tags'][0]

    # get xml configuration
    xml_list = []
    ind_xml = 0
    gcp_xml = get_configuration['sections'][0]['elements']
    if tags_to_apply == 'repeat_conf':
        gcp_xml = list(reversed(gcp_xml))
    while ind_xml < len(gcp_xml):
        for ele in gcp_xml[ind_xml]:
            xml_list.append(ele)
        ind_xml += 1

    # get remote configuration
    gcp_remote = gcp_remote_configuration(component, configuration)

    # default interval for 'wday' and 'time' to seconds
    if 'day' in xml_list and 'interval' in xml_list:
        gcp_xml[xml_list.index('interval')]['interval']['value'] = 1
    if 'wday' in xml_list and 'interval' in xml_list:
        gcp_xml[xml_list.index('interval')]['interval']['value'] = 604800

    # compare gcp_json with gcp_xml
    for remote_option in gcp_remote:
        if remote_option in xml_list:
            assert gcp_remote[remote_option] == gcp_xml[xml_list.index(remote_option)][remote_option]['value']
    if tags_to_apply == 'default_conf':
        assert gcp_remote['enabled'] == 'yes'
        assert gcp_remote['pull_on_start'] == 'yes'
        assert gcp_remote['max_messages'] == 100
        assert gcp_remote['logging'] == 'info'
        assert gcp_remote['interval'] == 3600
