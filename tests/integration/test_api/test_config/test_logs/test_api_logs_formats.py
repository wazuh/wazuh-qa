import os
import pytest
import re
import requests

from wazuh_testing.tools import PREFIX, API_LOG_FILE_PATH, API_JSON_LOG_FILE_PATH
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.api import API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASS, API_LOGIN_ENDPOINT, \
    get_login_headers

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# Variables

daemons_handler_configuration = {'daemons': ['wazuh-apid'], 'all_daemons': True}
test_directories = [os.path.join(PREFIX, 'test_logs')]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def send_request(login_attempts=5):
    """Send a login request to the API."""

    login_url = f"{API_PROTOCOL}://{API_HOST}:{API_PORT}{API_LOGIN_ENDPOINT}"

    for _ in range(login_attempts):
        response = requests.get(login_url, headers=get_login_headers(API_USER, API_PASS), verify=False, timeout=10)
        if response.status_code == 200: return True


def callback_json_output_info(line):
    group_brackets = r'({})'
    payload = r'"user": "(.+)", "ip": "(.+)", "http_method": "GET", "uri": "(GET ' + f'{API_LOGIN_ENDPOINT})"' + \
              r', "parameters": ' + f'{group_brackets}' + r', "body": ' + f'{group_brackets}' + \
              r', "time": "(\d*\.*\d+)s", "status_code": (\d+)'
    msg = r'{"timestamp": "(\d+\/\d+\/\d+ \d+:\d+:\d+)", "levelname": "(INFO)", "data": {"type": "request", ' \
          r'"payload": {' + f'{payload}' + r'}}}'
    match = re.match(msg, line)
    if not match:
        return None
    else:
        return match


def callback_plain_output_info(line):
    msg = r'(\d+/\d+/\d+ \d+:\d+:\d+) (INFO): (wazuh) (127.0.0.1) "(GET /security/user/authenticate)" with parameters' \
          r' ({}) and body ({}) done in (\d*\.*\d+)s: (\d+)'
    match = re.match(msg, line)
    if not match:
        return None
    else:
        return match


def callback_json_output_error(line):
    msg = r'{"timestamp": "(\d+/\d+/\d+ \d+:\d+:\d+)", "levelname": "(ERROR)", "data": {"type": "informative", ' \
          r'"payload": "(Timeout executing API request)"}}'
    match = re.match(msg, line)
    if not match:
        return None
    else:
        return match


def callback_plain_output_error(line):
    msg = r'(\d+/\d+/\d+ \d+:\d+:\d+) (ERROR): (Timeout executing API request)'
    match = re.match(msg, line)
    if not match:
        return None
    else:
        return match


# Tests
@pytest.mark.parametrize('tags_to_apply', [{'log_json_info'}, {'log_json_error'}, {'log_plain_info'},
                         {'log_plain_error'}, {'log_json_plain_info'}, {'log_json_plain_error'},
                         {'log_plain_json_info'}, {'log_plain_json_error'}])
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_api_logs_formats(tags_to_apply: list, get_configuration, configure_api_environment, clean_log_files,
                          daemons_handler, wait_for_start):
    wazuh_log_monitor = FileMonitor(API_LOG_FILE_PATH)
    json_log_monitor = FileMonitor(API_JSON_LOG_FILE_PATH)
    check_apply_test(tags_to_apply, get_configuration['tags'])
    current_formats = get_configuration['configuration']['logs']['format'].split(',')
    current_level = get_configuration['configuration']['logs']['level']

    send_request()

    if 'json' in current_formats:
        callback = callback_json_output_info if current_level == 'info' else callback_json_output_error
        json_result = json_log_monitor.start(timeout=15, callback=callback,
                                             error_message='The log was not the expected.').result()
    if 'plain' in current_formats:
        callback = callback_plain_output_info if current_level == 'info' else callback_plain_output_error
        plain_result = wazuh_log_monitor.start(timeout=15, callback=callback,
                                               error_message='The log was not the expected.').result()
    if len(current_formats) == 2:
        assert len(json_result.groups()) == len(plain_result.groups()), 'The length of the subgroups of the match is ' \
                                                                        'not equal.' \
                                                                        'Subgroups of the JSON match:' \
                                                                        f' {len(json_result.groups())}\n' \
                                                                        'Subgroups of the Plain match:' \
                                                                        f' {len(plain_result.groups())}\n'
        for _ in range(len(json_result.groups())):
            assert json_result.group(_+1) == plain_result.group(_+1), 'The values of the logs doesn\'t match.' \
                                                                      f'JSON log values: {json_result.groups()}\n' \
                                                                      f'Plain log values: {plain_result.groups()}\n'
