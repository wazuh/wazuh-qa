import os
import time
import pytest
import yaml
from wazuh_testing.tools.monitoring import make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import create_authd_request, validate_authd_response, AUTHD_KEY_REQUEST_TIMEOUT, \
                                insert_pre_existent_agents


# Data paths
data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(data_path, 'template_configuration.yaml')
tests_path = os.path.join(data_path, 'test_cases', 'valid_config')

# Configurations
configurations = load_wazuh_configurations(configurations_path, __name__)
local_internal_options = {'authd.debug': '2'}

# Tests
tests = []
test_case_ids = []
for file in os.listdir(tests_path):
    group_name = file.split(".")[0]
    file_tests = read_yaml(os.path.join(tests_path, file))
    tests = tests + file_tests
    test_case_ids = test_case_ids + [f"{group_name} {test_case['name']}" for test_case in file_tests]

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-authd', None, True), ('wazuh-db', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Functions
def validate_authd_logs(logs):
    for log in logs:
        log_monitor.start(timeout=AUTHD_KEY_REQUEST_TIMEOUT,
                          callback=make_callback(log, prefix=AUTHD_DETECTOR_PREFIX,
                                                 escape=True),
                          error_message=f"Expected error log does not occured: '{log}'")





# Fixtures
@pytest.fixture(scope='module')
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='function', params=tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param


def test_authd_force_options(get_current_test_case, configure_local_internal_options_module, override_authd_force_conf,
                             insert_pre_existent_agents, file_monitoring, restart_authd_function,
                             wait_for_authd_startup_function, connect_to_sockets_function, tear_down):

    authd_sock = receiver_sockets[0]
    validate_authd_logs(get_current_test_case.get('log', []))

    for stage in get_current_test_case['test_case']:
        # Reopen socket (socket is closed by manager after sending message with client key)
        authd_sock.open()
        authd_sock.send(create_authd_request(stage['input']), size=False)
        timeout = time.time() + AUTHD_KEY_REQUEST_TIMEOUT
        response = ''
        while response == '':
            response = authd_sock.receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        result, err_msg = validate_authd_response(response, stage['output'])
        assert result == 'success', f"Failed stage '{stage['description']}': {err_msg} Complete response: '{response}'"
        validate_authd_logs(stage.get('log', []))
