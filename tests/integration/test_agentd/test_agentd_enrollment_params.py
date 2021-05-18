# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import datetime
import os
import pytest
import yaml

import wazuh_testing.agent as ag
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORT = 1514
PROTOCOL = 'tcp'
INSTALLATION_FOLDER = WAZUH_PATH


def load_tests(path):
    """Load a yaml file from a path.

    Args:
        path (str): File location.

    Returns:
        dict: dictionary with the info from the YAML.
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
tests = load_tests(os.path.join(test_data_path, 'wazuh_enrollment_tests.yaml'))

# params = [{'SERVER_ADDRESS': SERVER_ADDRESS,}, {'PORT': REMOTED_PORT,},]

params = [{'SERVER_ADDRESS': SERVER_ADDRESS, }]
metadata = [{}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

authd_server = AuthdSimulator(server_address=SERVER_ADDRESS, key_path=ag.SERVER_KEY_PATH, cert_path=ag.SERVER_CERT_PATH)

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

remoted_server = None


def teardown():
    """End simulated remoted connection."""
    global remoted_server
    if remoted_server is not None:
        remoted_server.stop()


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=[''])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def configure_authd_server(request):
    """Initialize a simulated authd connection."""
    authd_server.start()
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)

    yield

    authd_server.shutdown()


def clean_log_file():
    """Clear the log file located in LOG_FILE_PATH."""
    open(LOG_FILE_PATH, 'w').close()


def override_wazuh_conf(configuration):
    """Apply custom settings on ossec.conf file.

    Settings are obtained from values located under "configuration" section of tests found in a YAML file.
    For this purpose, it stops the wazuh-agentd service, applies the settings and starts it again.

    Args:
        configuration (dict): New parameters to be applied.

    Raises:
        ValueError: If wazuh-agentd daemon cannot be started again.
    """
    # Stop Wazuh
    control_service('stop', daemon='wazuh-agentd')

    # Configuration for testing
    temp = get_temp_yaml(configuration)
    conf = load_wazuh_configurations(temp, __name__, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)

    # reset_client_keys
    ag.clean_client_keys_file()
    clean_log_file()
    ag.clean_password_file()
    if configuration.get('password'):
        parser = ag.AgentAuthParser()
        parser.add_password(password=configuration['password']['value'], isFile=True,
                            path=configuration.get('authorization_pass_path'))

    # Start Wazuh
    control_service('start', daemon='wazuh-agentd')


def get_temp_yaml(param):
    """Generate a new YAML configuration file by applying new parameters to it.

    Args:
        param (dict): New parameters to be applied.

    Returns:
        str: YAML stream with new configuration.
    """
    temp = os.path.join(test_data_path, 'temp.yaml')
    with open(configurations_path, 'r') as conf_file:
        enroll_conf = {'enrollment': {'elements': []}}
        for elem in param:
            if elem == 'password':
                continue
            enroll_conf['enrollment']['elements'].append({elem: {'value': param[elem]}})
        print(enroll_conf)
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(enroll_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


def check_time_to_connect(timeout):
    """Wait until client try connect.

    Args:
        timeout (int, optional): Maximum timeout. Default `-1`

    Returns:
        int: Integer with elapsed time in seconds.
    """
    def wait_connect(line):
        if 'Trying to connect to server' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    try:
        log_monitor.start(timeout=timeout + 2, callback=wait_connect)
    except TimeoutError:
        return -1

    final_line = log_monitor.result()
    initial_line = None
    elapsed_time = None

    with open(LOG_FILE_PATH, 'r') as log_file:
        lines = log_file.readlines()
        # find enrollment end
        for line in lines:
            if "INFO: Valid key received" in line:
                initial_line = line
                break

    if initial_line is not None and final_line is not None:
        form = '%H:%M:%S'
        initial_time = datetime.datetime.strptime(initial_line.split()[1], form).time()
        final_time = datetime.datetime.strptime(final_line.split()[1], form).time()
        initial_delta = datetime.timedelta(hours=initial_time.hour, minutes=initial_time.minute,
                                           seconds=initial_time.second)
        final_delta = datetime.timedelta(hours=final_time.hour, minutes=final_time.minute, seconds=final_time.second)
        elapsed_time = (final_delta - initial_delta).total_seconds()

    return elapsed_time


def check_log_error_conf(msg):
    """Check if a certain message has been written to the log files.

    Args:
        msg (str): string with the message.

    Returns:
        str: string with the complete line where the message is located or None if it is not found.
    """
    with open(LOG_FILE_PATH, 'r') as log_file:
        lines = log_file.readlines()
        for line in lines:
            if msg in line:
                return line
    return None


@pytest.mark.parametrize('test_case', tests, ids=[case['description'] for case in tests])
def test_agent_agentd_enrollment(configure_authd_server, configure_environment, test_case: list):
    """Test different situations that can occur on the wazuh-agentd daemon during agent enrollment.

    Args:
        configure_authd_server (fixture): Initializes a simulated authd connection.
        configure_environment (fixture): Configure a custom environment for testing.
        test_case (list): List of tests to be performed.
    """
    global remoted_server
    print(f'Test: {test_case["name"]}')
    if 'wazuh-agentd' in test_case.get("skips", []):
        pytest.skip("This test does not apply to wazuh-agentd")

    remoted_server = RemotedSimulator(protocol=PROTOCOL, mode='CONTROLLED_ACK', client_keys=ag.CLIENT_KEYS_PATH)

    configuration = test_case.get('configuration', {})
    ag.parse_configuration_string(configuration)
    ag.configure_enrollment(test_case.get('enrollment'), authd_server, configuration.get('agent_name'))
    try:
        override_wazuh_conf(configuration)
    except Exception:
        if test_case.get('expected_error') and not test_case.get('enrollment', {}).get('response'):
            # Expected to happen
            assert check_log_error_conf(test_case.get('expected_error')) is not None, \
                'Expected configuration error at ossec.conf file, fail log_check'
            return
        else:
            raise AssertionError(f'Configuration error at ossec.conf file')

    results = monitored_sockets.get_results(callback=(lambda y: [x.decode() for x in y]), timeout=20, accum_results=1)
    if test_case.get('enrollment') and test_case['enrollment'].get('response'):
        assert results[0] == ag.build_expected_request(configuration), \
            'Expected enrollment request message does not match'
        assert results[1] == test_case['enrollment']['response'].format(**ag.DEFAULT_VALUES), \
            'Expected response message does not match'
        assert results[1] == ag.check_client_keys_file(), 'Client key does not match'
    else:
        # Expected to happen
        assert check_log_error_conf(test_case.get('expected_error')) is not None, \
            'Expected configuration error at ossec.conf file, fail log_check'
        assert len(results) == 0, 'Enrollment message was not expected!'

    if configuration.get('delay_after_enrollment') and test_case.get('enrollment', {}).get('response'):
        time_delay = configuration.get('delay_after_enrollment')
        elapsed = check_time_to_connect(time_delay)
        assert ((time_delay - 2) < elapsed) and (elapsed < (time_delay + 2)), \
            f'Expected elapsed time between enrollment and connect does not match, should be around {time_delay} sec'

    return
