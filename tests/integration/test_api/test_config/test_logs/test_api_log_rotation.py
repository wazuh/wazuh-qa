'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: There is an API configuration option, called logs, which allows to log in 4 different ways ("json", "plain",
       "json,plain", and "plain,json") through the format field. When the API is configured with one of those values the
       logs are stored in the api.log and api.json files. When the machine time reaches midnight Wazuh rotates those
       files to /var/ossec/logs/api/<YEAR>/<MONTH>.
tier: 2
modules:
    - api
components:
    - manager
daemons:
    - wazuh-apid
os_platform:
    - linux
os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-monitord.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#logs
tags:
    - api
    - logs
    - logging
'''
import os
from datetime import datetime, timedelta
from time import sleep

import pytest

from wazuh_testing.tools import PREFIX, WAZUH_PATH
from wazuh_testing.tools.configuration import get_api_conf
from wazuh_testing.tools.time import TimeMachine

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# Variables
daemons_handler_configuration = {'all_daemons': True}
test_directories = [os.path.join(PREFIX, 'test_logs')]
date_format_str = '%Y-%m-%d %H:%M:%S'
date_format_str_2 = '%Y-%b-%d'
WAIT_FOR_MIDNIGHT = 5

# Configurations
configurations_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'conf_rotation.yaml')
configurations = get_api_conf(configurations_path)
tcase_ids = [f"format_{configuration['configuration']['logs']['format']}" for  configuration in configurations]

# Fixtures

@pytest.fixture(scope='module', params=configurations, ids=tcase_ids)
def get_configuration(request):
    """Get configurations from the module."""

    return request.param


@pytest.fixture(scope='function')
def time_machine_to_midnight():
    """Change the time of the machine to a defined time before midnight."""

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
    '''
    description: The test aims to check that the API log files (api.log and api.json) are rotated properly.
    wazuh_min_version: 4.4.0
    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_api_environment:
            type: fixture
            brief: Configure a custom environment for API testing.
        - clean_log_files:
            type: fixture
            brief: Reset the log files of the API and delete the rotated log files.
        - daemons_handler:
            type: fixture
            brief: Handle the Wazuh daemons.
        - wait_for_start:
            type: fixture
            brief: Wait until the API starts.
        - time_machine_to_midnight:
            type: fixture
            brief: Change the time of the machine to a defined time before midnight.
        - get_api_details:
            type: fixture
            brief: Send a request to the login endpoint, and get API details in a python dictionary.
    assertions:
        - Verify that the plain log file is rotated properly.
        - Verify that the json log file is rotated properly.
    input_description: The test gets the configuration from the YAML file, which contains the API configuration.
    expected_output:
        - The plain log was not rotated.
        - The json log was not rotated.
    tags:
        - api
        - logs
        - logging
    '''
    current_formats = get_configuration['configuration']['logs']['format'].split(',')

    yesterday = datetime.now() - timedelta(days=1)
    year, month, day = yesterday.strftime(date_format_str_2).split('-')

    get_api_details()
    sleep(WAIT_FOR_MIDNIGHT)

    if 'plain' in current_formats:
        file_exists = os.path.isfile(os.path.join(WAZUH_PATH, 'logs', 'api', year, month, f'api.log-{day}.gz'))
        assert file_exists, 'The plain log was not rotated.'
    if 'json' in current_formats:
        file_exists = os.path.isfile(os.path.join(WAZUH_PATH, 'logs', 'api', year, month, f'api.json-{day}.gz'))
        assert file_exists, 'The json log was not rotated.'
