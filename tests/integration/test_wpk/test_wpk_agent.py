'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Agents can be upgraded remotely. This upgrade is performed by the manager which
        sends each registered agent a WPK (Wazuh signed package) file that contains the files
        needed to upgrade the agent to the new version. These tests ensure, on the agent side,
        that the WPK upgrade works correctly.

components:
    - wpk

targets:
    - agent

daemons:
    - wazuh-authd
    - wazuh-remoted

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/agents/remote-upgrading/upgrading-agent.html

pytest_args:
    - wpk_version: Specify the version to upgrade
    - wpk_package_path: Specify the path to the wpk package

tags:
    - wpk
'''
import hashlib
import os
import platform
import pytest
import time
import requests
import subprocess
import yaml
import json

from wazuh_testing import tools
from wazuh_testing.tools.monitoring import make_callback, FileMonitor
from datetime import datetime
from wazuh_testing.tools import WAZUH_PATH, get_version, get_service
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file, count_file_lines
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import callback_detect_upgrade_ack_event, callback_upgrade_module_up, callback_exit_cleaning
from wazuh_testing import global_parameters


pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.win32,
              pytest.mark.tier(level=0), pytest.mark.agent]

sys_platform = platform.system()

folder = 'etc' if sys_platform == 'Linux' else '.'
upgrade_result_folder = 'var/upgrade' if sys_platform != "Windows" else 'upgrade'

DEFAULT_UPGRADE_SCRIPT = 'upgrade.sh' if sys_platform != "Windows" else 'upgrade.bat'

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder, 'client.keys')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'manager.cert')
UPGRADE_RESULT_PATH = os.path.join(WAZUH_PATH, upgrade_result_folder, 'upgrade_result')
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "tcp"
mark_skip_agentLinux = pytest.mark.skipif(get_service() == 'wazuh-agent' and
                                          sys_platform == 'Linux', reason="It will be blocked by wazuh/wazuh#9763")

if not global_parameters.wpk_version:
    raise Exception("The WPK package version must be defined by parameter. See README.md")
if global_parameters.wpk_package_path is None:
    raise ValueError("The WPK package path must be defined by parameter. See README.md")

version_to_upgrade = global_parameters.wpk_version[0]
package_path = global_parameters.wpk_package_path[0]

_agent_version = get_version()

error_msg = ''
ver_split = _agent_version.replace("v", "").split(".")
if int(ver_split[0]) >= 4 and int(ver_split[1]) >= 1:
    error_msg = 'Could not chmod' \
        if sys_platform != "Windows" else \
        'Error executing command'
else:
    error_msg = 'err Could not chmod' \
        if sys_platform != "Windows" else \
        'err Cannot execute installer'


time_to_sleep_until_backup = 10
time_to_sleep_until_stop = 1
wait_upgrade_process_timeout = 240
timeout_ack_response = 300
timeout_agent_exit = 250
timeout_upgrade_module_start = 200

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
    """ Loads a yaml file from a path.

    Args:
        String: Full path of yaml file.
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
configurations_path = os.path.join(test_data_path, 'wazuh_agent_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params,
                                           metadata=test_metadata)

remoted_simulator = None


def callback_agent_req(id_req):
    msg = '#! req {id_req}'
    return make_callback(pattern=msg, prefix=r'.*wazuh-agentd.*')


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
                                         mode='CONTROLLED_ACK',
                                         start_on_init=False,
                                         client_keys=CLIENT_KEYS_PATH)

    ver_split = _agent_version.replace("v", "").split(".")
    ver_major = ver_split[0]
    ver_minor = ver_split[1]
    if int(ver_split[0]) >= 4 and int(ver_split[1]) >= 1:
        remoted_simulator.set_wcom_message_version(f"{ver_major}.{ver_minor}")
    else:
        remoted_simulator.set_wcom_message_version(None)

    # Clean client.keys file
    truncate_file(CLIENT_KEYS_PATH)
    time.sleep(time_to_sleep_until_stop)

    control_service('stop')
    agent_auth_pat = 'bin' if sys_platform != "Windows" else ''
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
    current_plaform = sys_platform.lower()
    protocol = 'http://' if metadata['use_http'] else 'https://'
    wpk_repo = package_path
    architecture = 'x86_64'
    wpk_file_path = ''
    # Generating file name
    if current_plaform == "windows":
        wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_version,
                                                    current_plaform)
        wpk_url = protocol + wpk_repo + "windows/" + wpk_file
        wpk_file_path = os.path.join(WAZUH_PATH, 'tmp', wpk_file)
    elif current_plaform == "darwin":
        wpk_file = "wazuh_agent_{0}_macos_{1}.wpk"\
                .format(agent_version, architecture)
        wpk_url = protocol + wpk_repo \
            + "macos/" + architecture + "/pkg/" + wpk_file
        wpk_file_path = os.path.join(WAZUH_PATH, 'var', wpk_file)
    else:
        wpk_file = "wazuh_agent_{0}_linux_{1}.wpk"\
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

    if get_version() != metadata["initial_version"]:
        if sys_platform == 'Windows':
            try:
                control_service('stop')
            except ValueError:
                pass
            time.sleep(time_to_sleep_until_backup)
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

    if sys_platform == 'Windows':
        try:
            control_service('stop')
        except ValueError:
            pass
        time.sleep(time_to_sleep_until_backup)
        backup_path = os.path.join(WAZUH_PATH, 'backup')
        subprocess.call(['robocopy', backup_path, WAZUH_PATH,
                         '/E', '/IS', '/NFL', '/NDL', '/NJH', '/NP', '/NS', '/NC'])
    else:
        backup_file_start = f'backup_{metadata["initial_version"]}_[' \
                            f'{datetime.strftime(datetime.now(), "%m-%d-%Y")}'
        backups_files = [x for x in sorted(os.listdir(os.path.join(WAZUH_PATH,
                                                                   'backup')))
                         if backup_file_start in x]
        if len(backups_files) > 0:
            subprocess.call(['tar', 'xzf', f'{WAZUH_PATH}/backup/{backups_files[-1]}',
                            '-C', '/'])


@mark_skip_agentLinux
def test_wpk_agent(get_configuration, prepare_agent_version, download_wpk,
                   configure_environment, start_agent):
    '''
    description: Upgrade the agent by WPK package, checking
                 the expected messages are correct.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - prepare_agent_version:
            type: fixture
            brief: Prepare the initial agent version to match the expected.
        - download_wpk:
            type: fixture
            brief: Download the WPK package to upgrade the agent.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - start_agent:
            type: fixture
            brief: Start the agent, as well as the remoted and authd simulators.

    input_description: Test case metadata

    assertions:
        - Verify that initial agent version matches the expected
        - Verify the successful upgrade proccess
        - Verify the upgrade result code is the expected or the error message is the expected
        - Verify notification status was the expected
        - Verify the end version matches the expected

    expected_output:
        - r'Upgrade process result'
        - r'Upgrade result code'
        - r'Notification status'
        - r'End version'

    tags:
        - wpk
    '''
    metadata = get_configuration['metadata']
    expected = metadata['results']

    # Extract initial Wazuh Agent version
    assert get_version() == metadata["initial_version"], \
           'Initial version does not match Expected for agent'

    upgrade_process_result, upgrade_exec_message = \
        remoted_simulator.wait_upgrade_process(timeout=wait_upgrade_process_timeout)
    assert upgrade_process_result == expected['upgrade_ok'], \
           'Upgrade process result was not the expected'
    if upgrade_process_result:
        upgrade_result_code = None
        if expected['result_code'] == 0 and _agent_version == version_to_upgrade:
            exp_json = json.loads(upgrade_exec_message)
            upgrade_result_code = int(exp_json['message'])
        else:
            exp_json = json.loads(upgrade_exec_message)
            upgrade_result_code = int(exp_json['message'])
        assert upgrade_result_code == expected['result_code'], \
               f'Expected upgrade result code was {expected["result_code"]} ' \
               f'but obtained {upgrade_result_code} instead'
    else:
        if _agent_version == version_to_upgrade and not metadata['simulate_interruption']:
            exp_json = json.loads(upgrade_exec_message)
            upgrade_exec_message = str(exp_json['message'])
        assert upgrade_exec_message == expected['error_message'], 'Expected error message does not match'

    if upgrade_process_result and expected['receive_notification']:
        if sys_platform not in ['win32', 'Windows']:
            max_retries_truncate_file = 100
            lines = count_file_lines(tools.LOG_FILE_PATH)
            truncate_file_lines = lines
            while truncate_file_lines >= lines and max_retries_truncate_file > 0:
                --max_retries_truncate_file
                truncate_file_lines = count_file_lines(tools.LOG_FILE_PATH)
                time.sleep(1)
        else:
            truncate_file(tools.LOG_FILE_PATH)

        wazuh_log_monitor = FileMonitor(tools.LOG_FILE_PATH)

        if metadata['simulate_rollback']:

            if sys_platform not in ['win32', 'Windows']:
                wazuh_log_monitor.start(timeout=timeout_agent_exit,
                                        error_message="Error agentd not stopped",
                                        callback=callback_exit_cleaning())

            wazuh_log_monitor.start(timeout=timeout_upgrade_module_start,
                                    error_message="Upgrade module did not start",
                                    callback=callback_upgrade_module_up())

            remoted_simulator.change_default_listener = True

        event = wazuh_log_monitor.start(timeout=timeout_ack_response, error_message='ACK event not received',
                                                   callback=callback_detect_upgrade_ack_event).result()
        result = event['parameters']

        if result is not None:
            status = result['status']
            assert status == expected['status'], \
                   'Notification status did not match expected'
        else:
            assert not expected['receive_notification'], 'Notification was expected but was not received'

    if expected['upgrade_ok'] and not metadata['simulate_rollback']:
        assert get_version() == metadata['agent_version'], 'End version does not match expected!'
    else:
        assert get_version() == metadata['initial_version'], 'End version does not match expected!'
