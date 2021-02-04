# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    modify_file, delete_file, callback_detect_event, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('sleep, tags_to_apply', [
    (0.25, {'ossec_conf'}),
    (0.5, {'ossec_conf'}),
    (0.75, {'ossec_conf'}),
    (1, {'ossec_conf'}),
    (1.25, {'ossec_conf'}),
    (1.50, {'ossec_conf'}),
    (1.75, {'ossec_conf'}),
    (2, {'ossec_conf'})
])
def test_regular_file_changes(sleep, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                              wait_for_fim_start):
    """
    Check if syscheckd detects regular file changes (add, modify, delete) with a very specific delay between every
    action.

    Parameters
    ----------
    sleep : float
        Delay in seconds between every action.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file = 'regular'
    create_file(REGULAR, path=testdir1, name=file, content='')
    time.sleep(sleep)
    modify_file(path=testdir1, name=file, new_content='Sample')
    time.sleep(sleep)
    delete_file(path=testdir1, name=file)

    try:
        events = wazuh_log_monitor.start(timeout=max(sleep * 3, global_parameters.default_timeout),
                                         callback=callback_detect_event, accum_results=3,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event').result()
        for ev in events:
            validate_event(ev)
    except TimeoutError as e:
        if get_configuration['metadata']['fim_mode'] == 'whodata':
            pytest.xfail(reason='Xfailing due to issue: https://github.com/wazuh/wazuh/issues/4710')
        else:
            raise e
