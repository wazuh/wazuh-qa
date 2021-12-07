'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       This tests will check if the server address specified in the configuration is a valid
       address or not.

tier: 0

modules:
    - agentd

components:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - linux
    - windows

references:
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#address

tags:
    - server_address
'''
import os
import subprocess
import pytest
from time import sleep

from wazuh_testing.tools import HOSTS_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, DEFAULT_WAIT_FILE_TIMEOUT
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import agent


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
daemons_handler_configuration = {'daemons': ['wazuh-agentd'], 'ignore_errors': True}
local_internal_options = {'agent.debug': '2'}

parameters = [
    {'SERVER_ADDRESS': 'MANAGER_IP'},                               # Invalid server address
    {'SERVER_ADDRESS': '172.28.128.hello'},                         # Could not resolve hostname
    {'SERVER_ADDRESS': '172.28.128.12'},                            # Valid IP, unable to connect (IPv4)
    {'SERVER_ADDRESS': '::ffff:ac1c:800c'},                         # Valid IP, unable to connect (IPv6 compressed)
    {'SERVER_ADDRESS': '0000:0000:0000:0000:0000:ffff:ac1c:800c'},  # Valid IP, unable to connect (IPv6 expanded)
    {'SERVER_ADDRESS': 'unable'},                                   # Resolve hostname, valid IP, unable to connect (IPv4)
    {'SERVER_ADDRESS': 'unable6compressed'},                        # Resolve hostname, valid IP, unable to connect (IPv6 compressed)
    {'SERVER_ADDRESS': 'unable6'}                                   # Resolve hostname, valid IP, unable to connect (IPv6 expanded)
]

metadata = [
    {'server_address': 'MANAGER_IP',                              'invalid_address': True,  'resolve_hostname': False},
    {'server_address': '172.28.128.hello',                        'invalid_address': False, 'resolve_hostname': False},
    {'server_address': '172.28.128.12',                           'invalid_address': False, 'resolve_hostname': True},
    {'server_address': '::ffff:ac1c:800c',                        'invalid_address': False, 'resolve_hostname': True},
    {'server_address': '0000:0000:0000:0000:0000:ffff:ac1c:800c', 'invalid_address': False, 'resolve_hostname': True},
    {'server_address': 'unable', 'invalid_address': False, 'resolve_hostname': True, 'host_ip': '172.28.128.12'},
    {'server_address': 'unable6compressed', 'invalid_address': False, 'resolve_hostname': True, 'host_ip': '::ffff:ac1c:800c'},
    {'server_address': 'unable6', 'invalid_address': False, 'resolve_hostname': True, 'host_ip': '0000:0000:0000:0000:0000:ffff:ac1c:800c'}
]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['SERVER_IP']}" for x in parameters]

@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

@pytest.fixture(scope="module")
def edit_hosts(get_configuration):
    if 'host_ip' in get_configuration['metadata']:
        with open(HOSTS_FILE_PATH, 'r+') as file:
            original_content = file.read()

            new_content = get_configuration['metadata']['host_ip'] + ' ' + get_configuration['metadata']['server_address']
            file.write(new_content)

    yield

    if 'host_ip' in get_configuration['metadata']:
        with open(HOSTS_FILE_PATH, 'w') as file:
            file.write(original_content)

def test_agentd_server_configuration(get_configuration, configure_environment, configure_local_internal_options_module,
                edit_hosts, daemons_handler, file_monitoring):


    cfg = get_configuration['metadata']
    if cfg['invalid_address']:
        callback = agent.callback_invalid_server_address(cfg['server_address'])
        log_monitor.start(timeout=DEFAULT_WAIT_FILE_TIMEOUT, callback=callback,
                                error_message="The expected 'Invalid server address found' message has not been produced")
    else:
        if not cfg['resolve_hostname']:
            callback = agent.callback_could_not_resolve_hostname(cfg['server_address'])
            log_monitor.start(timeout=DEFAULT_WAIT_FILE_TIMEOUT, callback=callback,
                                    error_message="The expected 'Could not resolve hostname' message has not been produced")
        else:
            ip = cfg['host_ip'] if 'host_ip' in cfg else cfg['server_address']
            callback = agent.callback_unable_to_connect(ip)
            log_monitor.start(timeout=DEFAULT_WAIT_FILE_TIMEOUT, callback=callback,
                                    error_message="The expected 'Unable to connect to' message has not been produced")
