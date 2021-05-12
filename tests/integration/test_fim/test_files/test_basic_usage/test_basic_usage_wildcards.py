# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
from wazuh_testing import global_parameters, logger
from wazuh_testing.fim import CHECK_ALL, LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]
test_subdirectories = ['simple1', 'simple2', 'simple3']

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_wildcards.yml')

# configurations

conf_params = {'TEST_WILDCARDS_START': [os.path.join(test_folder, 'simple?'),
os.path.join(test_folder, 'simp*'), os.path.join(test_folder, '*ple?')], 'FIM_MODE': ['scheduled', 'realtime', "whodata"],
 'MODULE_NAME': __name__}
parameters, metadata = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def extra_configuration_before_yield():

    for sub_directory in test_subdirectories:
        if not os.path.exists(os.path.join(test_folder, sub_directory)):
            os.mkdir(os.path.join(test_folder, sub_directory))


'''
def extra_configuration_after_yield():
    for sub_directory in test_subdirectories:
        if os.path.exists(os.path.join(test_folder, sub_directory)):
            os.rmdir(os.path.join(test_folder, sub_directory))
'''

# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('parent_folder', [
    test_folder
])
@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_wildcards_start'}
])
@pytest.mark.parametrize('subfolder_name, file_name, encoding, checkers, triggers_event', [
    pytest.param('simple1', 'regular1', None, {CHECK_ALL}, True),
    pytest.param('simple2', '*.log', None, {CHECK_ALL}, True),
    pytest.param('simple3', '*.*', None, {CHECK_ALL}, True),

    pytest.param('imple', 'regular1', None, {CHECK_ALL}, False),
    pytest.param('simble1', 'regular1', None, {CHECK_ALL}, False),
    ])
def test_basic_usage_wildcards(parent_folder, subfolder_name, file_name, encoding, checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_fim_start, triggers_event):
    """
    Check if syscheckd detects regular file changes with wildcards (add, modify, delete)

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    checkers : dict
        Syscheck checkers (check_all).
    """

    if sys.platform == 'win32':
        if "?" or "*" in file_name:
            pytest.skip("Windows can't create files with wildcards.")

    check_apply_test(tags_to_apply, get_configuration['tags'])
    mult = 1 if sys.platform == 'win32' else 2

    if encoding is not None:
        file_name = file_name.encode(encoding)
        parent_folder = parent_folder.encode(encoding)

    folder = os.path.join(parent_folder, subfolder_name)

    regular_file_cud(folder, wazuh_log_monitor, file_list=[file_name],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout * mult, options=checkers, encoding=encoding,
                     triggers_event=triggers_event)
