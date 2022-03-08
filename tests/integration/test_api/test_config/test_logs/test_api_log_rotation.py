import os
from datetime import datetime, timedelta
from time import sleep

import pytest

from wazuh_testing.tools import PREFIX, API_LOG_FILE_PATH, API_JSON_LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.configuration import get_api_conf
from wazuh_testing.tools.time import TimeMachine

# Variables
daemons_handler_configuration = {'all_daemons': True}
test_directories = [os.path.join(PREFIX, 'test_logs')]
date_format_str = '%Y-%m-%d %H:%M:%S'
date_format_str_2 = '%Y-%b-%d %H:%M:%S'
WAIT_FOR_MIDNIGHT = 5

# Configurations
configurations_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'conf_rotation.yaml')
configurations = get_api_conf(configurations_path)
tcase_ids = [f"format_{configuration['configuration']['logs']['format']}" for  configuration in configurations]

# Fixtures

@pytest.fixture(scope='module', params=configurations, ids=tcase_ids)
def get_configuration(request):
    return request.param


@pytest.fixture(scope='module')
def time_machine_to_midnight():
    now = datetime.strptime(datetime.now().strftime(date_format_str), date_format_str)
    hours, minutes, seconds = [int(x) for x in now.strftime(date_format_str)[-8:].split(':')]
    before_midnight_datetime = (now + timedelta(days=1)) - timedelta(hours=hours, minutes=minutes, seconds=seconds)
    before_midnight_datetime -= timedelta(seconds=WAIT_FOR_MIDNIGHT)
    current_datetime = datetime.now()
    interval = before_midnight_datetime - current_datetime

    TimeMachine.travel_to_future(interval)
    sleep(WAIT_FOR_MIDNIGHT)

    yield

    TimeMachine.time_rollback()


# Tests

@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_api_log_rotation(get_configuration, configure_api_environment, clean_log_files, daemons_handler,
                          wait_for_start, time_machine_to_midnight, get_api_details):
    current_formats = get_configuration['configuration']['logs']['format'].split(',')

    yesterday = datetime.now() - timedelta(days=1)
    year, month, day = yesterday.strftime(date_format_str_2).split(' ')[0].split('-')

    get_api_details()
    sleep(WAIT_FOR_MIDNIGHT)

    if 'plain' in current_formats:
        file_exists = os.path.isfile(os.path.join(WAZUH_PATH, 'logs', 'api', year, month, f'api-{day}.log.gz'))
        assert file_exists, 'The plain log was not rotated.'
    if 'json' in current_formats:
        file_exists = os.path.isfile(os.path.join(WAZUH_PATH, 'logs', 'api', year, month, f'api.json-{day}.gz'))
        assert file_exists, 'The json log was not rotated.'
