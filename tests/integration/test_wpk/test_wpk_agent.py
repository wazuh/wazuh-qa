# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import hashlib
import os
import platform
import pytest
import time
import requests
import subprocess
import yaml

from configobj import ConfigObj
from datetime import datetime
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.tier(level=0), pytest.mark.agent]

folder = 'etc' if platform.system() == 'Linux' else ''

DEFAULT_UPGRADE_SCRIPT = 'upgrade.sh' if platform.system() == 'Linux' else 'upgrade.bat'
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder,'client.keys') #for unix add 'etc'
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "tcp"

# Test will varying according to agent version. This test should be tried with at least:
# 1. v3.13.1
# 2. v4.0.0
config_file_path = os.path.join(WAZUH_PATH, 'etc', 'ossec-init.conf')
_config = ConfigObj(config_file_path)
_agent_version = _config['VERSION']

test_metadata = [
    # 1. Upgrade from initial_version to v4.0.0
    {
        'protocol': PROTOCOL,
        'initial_version': _agent_version,
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': DEFAULT_UPGRADE_SCRIPT,
        'chunk_size': 16384,
        'simulate_interruption': False,
        'simulate_rollback': False,
        'results': {
            'upgrade_ok': True,
            'result_code': 0,
            'receive_notification': True,
            'status': 'Done',   
        }
    },
    # 2. False upgrade script parameter
    {
        'protocol': PROTOCOL,
        'initial_version': _agent_version,
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': 'fake_upgrade.sh',
        'chunk_size': 16384,
        'simulate_interruption': False,
        'simulate_rollback': False,
        'results': {
            'upgrade_ok': False,
            'error_message': 'err Could not chmod',
            'receive_notification': False,
        }
    },
    # 3. Simulate an interruption
    {
        'protocol': PROTOCOL,
        'initial_version': _agent_version,
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': DEFAULT_UPGRADE_SCRIPT,
        'chunk_size': 16384,
        'simulate_interruption': True,
        'simulate_rollback': False,
        'results': {
            'upgrade_ok': False,
            'error_message': 'Request confirmation never arrived',
            'receive_notification': False,
        }
    }
]

if _agent_version == 'v3.13.1':
    test_metadata += [{
        # 4. Simulate a rollback (v3.13.1)
        'protocol': PROTOCOL,
        'initial_version': 'v3.13.1',
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': DEFAULT_UPGRADE_SCRIPT,
        'chunk_size': 16384,
        'simulate_interruption': False,
        'simulate_rollback': True,
        'results': {
            'upgrade_ok': True,
            'result_code': 0,
            'receive_notification': False,
        }
    }]
elif _agent_version == 'v4.0.0':
    test_metadata += [{
        # 5. Simulate a rollback (v4.0.0)
        'protocol': PROTOCOL,
        'initial_version': 'v4.0.0',
        'agent_version': 'v4.0.0',
        'use_http': False,
        'upgrade_script': DEFAULT_UPGRADE_SCRIPT,
        'chunk_size': 16384,
        'simulate_interruption': False,
        'simulate_rollback': True,
        'results': {
            'upgrade_ok': True,
            'result_code': 0,
            'receive_notification': True,
            'status': 'Failed',   
        }
    }]

params = [
    {
        'CRYPTO': CRYPTO,
        'SERVER_ADDRESS': SERVER_ADDRESS,
        'REMOTED_PORT': 1514,
        'PROTOCOL': PROTOCOL
    } for x in range(0, len(test_metadata))
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
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=test_metadata)

# configurations = configurations[-1:]

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
    
    remoted_simulator.start(custom_listener=remoted_simulator.upgrade_listener, args=(metadata['filename'], metadata['filepath'], metadata['chunk_size'], metadata['upgrade_script'], metadata['sha1'], 
        metadata['simulate_interruption'], metadata['simulate_rollback']))
    
    control_service('stop')
    subprocess.call([f'{WAZUH_PATH}/bin/agent-auth', '-m', SERVER_ADDRESS])
    control_service('start') 

    yield

    remoted_simulator.stop()
    authd_simulator.shutdown()
    
@pytest.fixture(scope="function")
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

@pytest.fixture(scope="function")
def prepare_agent_version(get_configuration):
    metadata = get_configuration['metadata']
    config = ConfigObj(config_file_path)

    if config['VERSION'] != metadata["initial_version"]:
        # We should change initial version to match expected
        backup_file_start = f'backup_{metadata["initial_version"]}_[{datetime.strftime(datetime.now(), "%m-%d-%Y")}'
        backups_files = [x for x in sorted(os.listdir(os.path.join(WAZUH_PATH, 'backup'))) if backup_file_start in x]

        if len(backups_files) > 0:
            subprocess.call(['tar', 'xzf', f'{WAZUH_PATH}/backup/{backups_files[-1]}', '-C', '/'])
        else: 
            raise Exception('Expected initial version for test does not match current agent version and there is no backup available to restore it')
    
    yield

    
    backup_file_start = f'backup_{metadata["initial_version"]}_[{datetime.strftime(datetime.now(), "%m-%d-%Y")}'
    backups_files = [x for x in sorted(os.listdir(os.path.join(WAZUH_PATH, 'backup'))) if backup_file_start in x]

    subprocess.call(['tar', 'xzf', f'{WAZUH_PATH}/backup/{backups_files[-1]}', '-C', '/'])
    # tar xzf ${DIRECTORY}/backup/backup_${VERSION}_[${BDATE}].tar.gz

def test_wpk_agent(get_configuration, prepare_agent_version, download_wpk, configure_environment, start_agent):
    metadata = get_configuration['metadata']
    expected = metadata['results']
    
    # Extract initial Wazuh Agent version
    config = ConfigObj(config_file_path)
    assert config['VERSION'] == metadata["initial_version"], 'Initial version does not match Expected for agent'

    upgrade_process_result, upgrade_exec_message = remoted_simulator.wait_upgrade_process(timeout=180)
    assert upgrade_process_result == expected['upgrade_ok'], 'Upgrade process result was not the expected'
    if upgrade_process_result:
        upgrade_result_code = int(upgrade_exec_message.split(' ')[1])
        assert upgrade_result_code == expected['result_code'], f'Expected upgrade result code was {expected["result_code"]} but obtained {upgrade_result_code} instead'
    else:
        assert upgrade_exec_message == expected['error_message'], f'Expected error message does not match'
    if upgrade_process_result and expected['receive_notification']:
        result = remoted_simulator.wait_upgrade_notification(timeout=180)
        if result is not None:
            data = result['data']
            status = result['status']
            assert status == expected['status'], 'Notification status did not match expected'
        else:
            assert expected['receive_notification'] == False, 'Notification was expected but was not received'

    config = ConfigObj(config_file_path)
    
    if expected['upgrade_ok'] and not metadata['simulate_rollback']:
        assert config['VERSION'] == metadata['agent_version'], 'End version does not match expected!'
    else: 
        assert config['VERSION'] == metadata['initial_version'], 'End version does not match expected!'
