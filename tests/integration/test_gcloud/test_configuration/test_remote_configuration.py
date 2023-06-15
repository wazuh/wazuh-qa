'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'gcp-pubsub' module uses it to fetch different kinds of events
       (Data access, Admin activity, System events, DNS queries, etc.) from the
       Google Cloud infrastructure. Once events are collected, Wazuh processes
       them using its threat detection rules. Specifically, these tests
       will check if the remote configuration used by GCP matches
       the local one set in the 'ossec.conf' file.

components:
    - gcloud

suite: configuration

targets:
    - agent
    - manager

daemons:
    - wazuh-monitord
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/gcp-pubsub.html

tags:
    - config
    - remote
'''
import os
import pytest
import json
import socket
import sys

from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH, get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, SocketController

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

enabled = 'yes'
pull_on_start = 'yes'
max_messages = 200
interval = '2h'
day = 9
wday = 'tuesday'
time = '08:00'
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
component = "wmodules"
configuration = "wmodules"
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_remote_conf.yaml')

# configurations

daemons_handler_configuration = {'daemons': ['wazuh-modulesd'], 'ignore_errors': True}
monitoring_modes = ['scheduled']
conf_params = {'PROJECT_ID': global_parameters.gcp_project_id,
               'SUBSCRIPTION_NAME': global_parameters.gcp_subscription_name,
               'CREDENTIALS_FILE': global_parameters.gcp_credentials_file, 'ENABLED': enabled,
               'PULL_ON_START': pull_on_start, 'MAX_MESSAGES': max_messages,
               'INTERVAL': interval, 'DAY': day, 'WDAY': wday,
               'TIME': time, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params,
                       modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)
force_restart_after_restoring = False


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def get_remote_configuration(component_name, config):
    socket_path = os.path.join(WAZUH_PATH, 'queue', 'sockets')
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
            for element in remote_configuration['wmodules']:
                if 'gcp-pubsub' in element:
                    remote_configuration_gcp = element['gcp-pubsub']
        else:
            s.close()
            raise ValueError(rec_msg_ok)
    except UnboundLocalError as error:
        s.close()
        raise TimeoutError(error)
    return remote_configuration_gcp


@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not have support for Google Cloud integration.")
def test_remote_configuration(get_configuration, configure_environment, reset_ossec_log, daemons_handler_module,
                              wait_for_gcp_start):
    '''
    description: Check if the remote configuration matches the local configuration of the 'gcp-pubsub' module.
                 For this purpose, the test will use different settings and get the remote configuration applied.
                 Then, it will verify that the default and custom local options match. It will also verify that,
                 when repeated options are used in the configuration, the last one detected is the one applied.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - wait_for_gcp_start:
            type: fixture
            brief: Wait for the 'gpc-pubsub' module to start.

    assertions:
        - Verify that the remote configuration used by GCP matches the local one set in the 'ossec.conf' file.

    input_description: Different test cases are contained in an external YAML file (wazuh_remote_conf.yaml)
                       which includes configuration settings for the 'gcp-pubsub' module. The GCP access
                       credentials can be found in the 'configuration_template.yaml' file.

    expected_output:
        - The current configuration settings from GCP to compare them with the local ones.
    '''
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

    # default path of credentials file
    if WAZUH_PATH not in gcp_xml[xml_list.index('credentials_file')]['credentials_file']['value']:
        credentials_path = gcp_xml[xml_list.index('credentials_file')]['credentials_file']['value']
        gcp_xml[xml_list.index('credentials_file')]['credentials_file']['value'] = os.path.join(WAZUH_PATH,
                                                                                                credentials_path)
    # default interval for 'wday' and 'time' to seconds
    if 'day' in xml_list and 'interval' in xml_list:
        gcp_xml[xml_list.index('interval')]['interval']['value'] = 1
    if 'wday' in xml_list and 'interval' in xml_list:
        gcp_xml[xml_list.index('interval')]['interval']['value'] = 604800

    # get remote configuration
    gcp_remote = get_remote_configuration(component, configuration)

    # compare gcp_json with gcp_xml
    for remote_option in gcp_remote:
        if remote_option in xml_list:
            assert gcp_remote[remote_option] == gcp_xml[xml_list.index(remote_option)][remote_option]['value']
    if tags_to_apply == 'default_conf':
        assert gcp_remote['enabled'] == 'yes'
        assert gcp_remote['pull_on_start'] == 'yes'
        assert gcp_remote['max_messages'] == 100
        assert gcp_remote['interval'] == 3600
