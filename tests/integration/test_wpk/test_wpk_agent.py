# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import os
import platform
import pytest
import time
import requests
import yaml

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

folder = 'etc' if platform.system() == 'Linux' else ''

DEFAULT_UPGRADE_SCRIPT = 'upgrade.sh' if platform.system() == 'Linux' else 'upgrade.bat'
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder,'client.keys') #for unix add 'etc'
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "tcp"

params = [
    {
        'CRYPTO': CRYPTO,
        'SERVER_ADDRESS': SERVER_ADDRESS,
        'REMOTED_PORT': 1514,
        'PROTOCOL': PROTOCOL
    },
    {
        'CRYPTO': CRYPTO,
        'SERVER_ADDRESS': SERVER_ADDRESS,
        'REMOTED_PORT': 1514,
        'PROTOCOL': PROTOCOL
    }
]
metadata = [
    {
        'protocol': PROTOCOL,
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': DEFAULT_UPGRADE_SCRIPT,
        'chunk_size': 16384,
        'results': {
            'upgrade_ok': True,
            'result_code': 0,
            'receive_notification': True,
            'status': 'Done',   
        }
    },
    {
        'protocol': PROTOCOL,
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': 'fake_upgrade.sh',
        'chunk_size': 16384,
        'results': {
            'upgrade_ok': False,
            'error_message': 'err Could not chmod',
            'receive_notification': False,
        }
    }
]

def load_tests(path):
    """ Loads a yaml file from a path 
    Retrun 
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

remoted_simulator = None 

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

@pytest.fixture(scope="function")
def start_agent(request, get_configuration):
    metadata = get_configuration['metadata']
    authd_simulator = AuthdSimulator(server_address=SERVER_ADDRESS, enorllment_port=1515)
    authd_simulator.start()
    global remoted_simulator
    remoted_simulator = RemotedSimulator(server_address=SERVER_ADDRESS, remoted_port=1514, protocol=metadata['protocol'], mode='CONTROLED_ACK',start_on_init=False)
    
    # Clean client.keys file
    truncate_file(CLIENT_KEYS_PATH)
    time.sleep(1)
    
    remoted_simulator.start(custom_listener=remoted_simulator.upgrade_listener, args=(metadata['filename'], metadata['filepath'], metadata['chunk_size'], metadata['upgrade_script'], metadata['sha1']))
    control_service('restart')  

    yield

    remoted_simulator.stop()
    authd_simulator.shutdown()
    
@pytest.fixture(scope="module")
def download_wpk(get_configuration):
    metadata = get_configuration['metadata']
    agent_version = metadata['agent_version']
    current_plaform = platform.system()
    protocol = 'http://' if metadata['use_http'] else 'https://'
    wpk_repo = 'packages.wazuh.com/4.x/wpk/'
    architecture = 'x86_64'
    # Generating file name
    if current_plaform == "windows":
        wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_version, current_plaform)
        wpk_url = protocol + wpk_repo + "windows/" + wpk_file
    else:
        wpk_file = "wazuh_agent_{0}_linux_{1}.wpk".format(agent_version, architecture)
        wpk_url = protocol + wpk_repo + "linux/" + architecture + "/" + wpk_file

    wpk_file_path = os.path.join(WAZUH_PATH, 'var', wpk_file)
    try:
        result = requests.get(wpk_url)
    except requests.exceptions.RequestException as e:
        pass
    
    if result.ok:
        with open(wpk_file_path, 'wb') as fd:
            for chunk in result.iter_content(chunk_size=128):
                fd.write(chunk)        
    else:
        error = "Can't access to the WPK file in {}".format(wpk_url)
    
    # Get SHA1 file sum
    sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()

    metadata = get_configuration.get('metadata')
    metadata['filename'] = wpk_file
    metadata['filepath'] = wpk_file_path
    metadata['sha1'] = sha1hash


def test_wpk_agent(get_configuration, download_wpk, configure_environment, start_agent):
    expected = get_configuration['metadata']['results']
    upgrade_process_result, upgrade_exec_message = remoted_simulator.wait_upgrade_process(timeout=60)
    assert upgrade_process_result == expected['upgrade_ok'], 'Upgrade process result was not the expected'
    if upgrade_process_result:
        upgrade_result_code = int(upgrade_exec_message.split(' ')[1])
        assert upgrade_result_code == expected['result_code'], f'Expected upgrade result code was {expected["result_code"]} but obtained {upgrade_result_code} instead'
    else:
        assert upgrade_exec_message == expected['error_message'], f'Expected error message does not match'
    if upgrade_process_result and expected['receive_notification']:
        result = remoted_simulator.wait_upgrade_notification(timeout=120)
        if result is not None:
            data = result['data']
            status = result['status']
            assert status == expected['status'], 'Notification status did not match expected'
