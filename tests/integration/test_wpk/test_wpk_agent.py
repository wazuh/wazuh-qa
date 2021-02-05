# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import hashlib
import json
import os
import platform
import subprocess
import time
from datetime import datetime

import pytest
import requests
import yaml
from configobj import ConfigObj
from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0),
              pytest.mark.agent]

folder = 'etc' if platform.system() == 'Linux' else ''

upgrade_result_folder = 'var/upgrade' if platform.system() == 'Linux' else 'upgrade'

DEFAULT_UPGRADE_SCRIPT = 'upgrade.sh' if platform.system() == 'Linux' \
    else 'upgrade.bat'
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder, 'client.keys')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'manager.cert')
UPGRADE_RESULT_PATH = os.path.join(WAZUH_PATH, upgrade_result_folder, 'upgrade_result')
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "tcp"

if not global_parameters.wpk_version:
    raise Exception("The WPK package version must be defined by parameter. See README.md")
version_to_upgrade = global_parameters.wpk_version[0]


# Test will varying according to agent version. This test should be tried
# with at least:
# 1. v3.13.2
# 2. v4.1.0
def get_current_version():
    if platform.system() == 'Linux':
        config_file_path = os.path.join(WAZUH_PATH, 'etc', 'ossec-init.conf')
        _config = ConfigObj(config_file_path)
        return _config['VERSION']

    else:
        version = None
        with open(os.path.join(WAZUH_PATH, 'VERSION'), 'r') as f:
            version = f.read()
            version = version[:version.rfind('\n')]
        return version


_agent_version = get_current_version()

error_msg = ''
ver_split = _agent_version.replace("v", "").split(".")
if int(ver_split[0]) >= 4 and int(ver_split[1]) >= 1:
    error_msg = 'Could not chmod' \
        if platform.system() == 'Linux' else \
        'Error executing command'
else:
    error_msg = 'err Could not chmod' \
        if platform.system() == 'Linux' else \
        'err Cannot execute installer'

test_metadata = [
    # 1. Upgrade from initial_version to new version
    {
        'protocol': PROTOCOL,
        'initial_version': _agent_version,
        'agent_version': version_to_upgrade,
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
        'agent_version': version_to_upgrade,
        'use_http': False,
        'upgrade_script': 'fake_upgrade.sh',
        'chunk_size': 16384,
        'simulate_interruption': False,
        'simulate_rollback': False,
        'results': {
            'upgrade_ok': False,
            'error_message': error_msg,
            'receive_notification': False,
        }
    },
    # 3. Simulate an interruption
    {
        'protocol': PROTOCOL,
        'initial_version': _agent_version,
        'agent_version': version_to_upgrade,
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

if _agent_version == 'v3.13.2':
    test_metadata += [{
        # 4. Simulate a rollback (v3.13.2)
        'protocol': PROTOCOL,
        'initial_version': 'v3.13.2',
        'agent_version': version_to_upgrade,
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
elif _agent_version == version_to_upgrade:
    test_metadata += [{
        # 5. Simulate a rollback (new version)
        'protocol': PROTOCOL,
        'initial_version': version_to_upgrade,
        'agent_version': version_to_upgrade,
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
    } for _ in range(0, len(test_metadata))
]


def load_tests(path):
    """ Loads a yaml file from a path
    Return
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params,
                                           metadata=test_metadata)

# configurations = configurations[-1:]

remoted_simulator = None


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope="function")
def start_agent(request, get_configuration):
    metadata = get_configuration['metadata']
    authd_simulator = AuthdSimulator(server_address=SERVER_ADDRESS,
                                     enrollment_port=1515,
                                     key_path=SERVER_KEY_PATH,
                                     cert_path=SERVER_CERT_PATH)
    authd_simulator.start()
    global remoted_simulator
    remoted_simulator = RemotedSimulator(server_address=SERVER_ADDRESS,
                                         remoted_port=1514,
                                         protocol=metadata['protocol'],
                                         mode='CONTROLED_ACK',
                                         start_on_init=False,
                                         client_keys=CLIENT_KEYS_PATH)

    ver_split = _agent_version.replace("v", "").split(".")
    if int(ver_split[0]) >= 4 and int(ver_split[1]) >= 1:
        remoted_simulator.setWcomMessageVersion('4.1')
    else:
        remoted_simulator.setWcomMessageVersion(None)

    # Clean client.keys file
    truncate_file(CLIENT_KEYS_PATH)
    time.sleep(1)

    control_service('stop')
    agent_auth_pat = 'bin' if platform.system() == 'Linux' else ''
    subprocess.call([f'{WAZUH_PATH}/{agent_auth_pat}/agent-auth', '-m',
                     SERVER_ADDRESS])
    control_service('start')

    remoted_simulator.start(custom_listener=remoted_simulator.upgrade_listener,
                            args=(metadata['filename'], metadata['filepath'],
                                  metadata['chunk_size'],
                                  metadata['upgrade_script'],
                                  metadata['sha1'],
                                  metadata['simulate_interruption'],
                                  metadata['simulate_rollback']))

    yield

    remoted_simulator.stop()
    authd_simulator.shutdown()


@pytest.fixture(scope="function")
def download_wpk(get_configuration):
    metadata = get_configuration['metadata']
    agent_version = metadata['agent_version']
    current_plaform = platform.system().lower()
    protocol = 'http://' if metadata['use_http'] else 'https://'
    wpk_repo = 'packages-dev.wazuh.com/trash/wpk/'
    architecture = 'x86_64'
    wpk_file_path = ''
    # Generating file name
    if current_plaform == "windows":
        wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_version,
                                                    current_plaform)
        wpk_url = protocol + wpk_repo + "windows/" + wpk_file
        wpk_file_path = os.path.join(WAZUH_PATH, 'tmp', wpk_file)
    else:
        wpk_file = "wazuh_agent_{0}_linux_{1}.wpk" \
            .format(agent_version, architecture)
        wpk_url = protocol + wpk_repo \
                  + "linux/" + architecture + "/" + wpk_file
        wpk_file_path = os.path.join(WAZUH_PATH, 'var', wpk_file)
    try:
        result = requests.get(wpk_url)
    except requests.exceptions.RequestException:
        raise Exception("The WPK package could not be obtained")

    if result.ok:
        with open(wpk_file_path, 'wb') as fd:
            for chunk in result.iter_content(chunk_size=128):
                fd.write(chunk)
    else:
        raise Exception("Can't access to the WPK file in {}".format(wpk_url))

    # Get SHA1 file sum
    sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()

    metadata = get_configuration.get('metadata')
    metadata['filename'] = wpk_file
    metadata['filepath'] = wpk_file_path
    metadata['sha1'] = sha1hash


@pytest.fixture(scope="function")
def prepare_agent_version(get_configuration):
    metadata = get_configuration['metadata']

    if os.path.exists(UPGRADE_RESULT_PATH):
        os.remove(UPGRADE_RESULT_PATH)

    if get_current_version() != metadata["initial_version"]:
        if platform.system() == 'Windows':
            try:
                control_service('stop')
            except ValueError:
                pass
            time.sleep(10)
            backup_path = os.path.join(WAZUH_PATH, 'backup')
            subprocess.call(['robocopy', backup_path, WAZUH_PATH,
                             '/E', '/IS', '/NFL', '/NDL', '/NJH',
                             '/NP', '/NS', '/NC'])
        else:
            # We should change initial version to match expected
            backup_file_start = f'backup_{metadata["initial_version"]}_[' \
                                f'{datetime.strftime(datetime.now(), "%m-%d-%Y")}'
            backups_files = [x for x in sorted(os.listdir(os.path.join(WAZUH_PATH,
                                                                       'backup')))
                             if backup_file_start in x]

            if len(backups_files) > 0:
                subprocess.call(['tar', 'xzf', f'{WAZUH_PATH}/backup/'
                                               f'{backups_files[-1]}', '-C', '/'])
            else:
                raise Exception('Expected initial version for test does not match'
                                ' current agent version and there is no backup '
                                'available to restore it')

    yield

    if platform.system() == 'Windows':
        try:
            control_service('stop')
        except ValueError:
            pass
        time.sleep(10)
        backup_path = os.path.join(WAZUH_PATH, 'backup')
        subprocess.call(['robocopy', backup_path, WAZUH_PATH,
                         '/E', '/IS', '/NFL', '/NDL', '/NJH', '/NP', '/NS', '/NC'])
    else:
        backup_file_start = f'backup_{metadata["initial_version"]}_[' \
                            f'{datetime.strftime(datetime.now(), "%m-%d-%Y")}'
        backups_files = [x for x in sorted(os.listdir(os.path.join(WAZUH_PATH,
                                                                   'backup')))
                         if backup_file_start in x]

        subprocess.call(['tar', 'xzf', f'{WAZUH_PATH}/backup/{backups_files[-1]}',
                         '-C', '/'])


def test_wpk_agent(get_configuration, prepare_agent_version, download_wpk,
                   configure_environment, start_agent):
    metadata = get_configuration['metadata']
    expected = metadata['results']

    # Extract initial Wazuh Agent version
    assert get_current_version() == metadata["initial_version"], \
        'Initial version does not match Expected for agent'

    upgrade_process_result, upgrade_exec_message = \
        remoted_simulator.wait_upgrade_process(timeout=240)
    assert upgrade_process_result == expected['upgrade_ok'], \
        'Upgrade process result was not the expected'
    if upgrade_process_result:
        upgrade_result_code = None
        if expected['result_code'] == 0 and _agent_version == version_to_upgrade:
            exp_json = json.loads(upgrade_exec_message)
            upgrade_result_code = int(exp_json['message'])
        else:
            upgrade_result_code = int(upgrade_exec_message.split(' ')[1])
        assert upgrade_result_code == expected['result_code'], \
            f'Expected upgrade result code was {expected["result_code"]} ' \
            f'but obtained {upgrade_result_code} instead'
    else:
        if _agent_version == version_to_upgrade and not metadata['simulate_interruption']:
            exp_json = json.loads(upgrade_exec_message)
            upgrade_exec_message = str(exp_json['message'])
        assert upgrade_exec_message == expected['error_message'], \
            f'Expected error message does not match'
    if upgrade_process_result and expected['receive_notification']:
        result = remoted_simulator.wait_upgrade_notification(timeout=180)
        if result is not None:
            status = result['status']
            assert status == expected['status'], \
                'Notification status did not match expected'
        else:
            assert not expected['receive_notification'], \
                'Notification was expected but was not received'

    if expected['upgrade_ok'] and not metadata['simulate_rollback']:
        assert get_current_version() == metadata['agent_version'], \
            'End version does not match expected!'
    else:
        assert get_current_version() == metadata['initial_version'], \
            'End version does not match expected!'
