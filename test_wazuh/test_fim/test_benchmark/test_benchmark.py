# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import shutil
import subprocess
import time
from collections import Counter
from datetime import timedelta

import pytest

from jq import jq
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1')]
testdir1 = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = [{'section': 'syscheck',
                   'new_values': [{'disabled': 'no'},
                                  {'directories': '/testdir1,/testdir2,/noexists'}],
                   'new_attributes': [{'directories': [{'check_all': 'yes'},
                                                       {'realtime': 'yes'}]}],
                   'checks': ['realtime']},
                  {'section': 'syscheck',
                   'new_values': [{'disabled': 'no'},
                                  {'directories': '/testdir1,/testdir2,/noexists'}],
                   'new_attributes': [{'directories': [{'check_all': 'yes'},
                                                       {'whodata': 'yes'}]}],
                   'checks': ['whodata']}
                  ]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.benchmark
@pytest.mark.parametrize('n_regular, folder, checks', [
    (10, testdir1, ['whodata', 'realtime']),
    (100, testdir1, ['realtime']),
    (1000, testdir1, ['whodata']),
    (10000, testdir1, ['realtime'])
])
def test_detect_regular_files(n_regular, folder, checks, get_configuration,
                              configure_environment):
    """Checks if a regular file creation is detected by syscheck"""
    if not set(checks).intersection(set(get_configuration['checks'])):
        pytest.skip("Does not apply to this config file")

    min_timeout = 30
    # Create text files
    for name in range(n_regular):
        with open(os.path.join(folder, f'regular_{name}'), 'w') as f:
            f.write('')

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=max(n_regular*0.01, min_timeout), callback=callback_detect_event,
                                    accum_results=n_regular).result()
    # Are the n_regular events of type 'added'?
    types = Counter(jq(".[].data.type").transform(events, multiple_output=True))

    assert(types['added'] == n_regular)

    # Are the n_regular events the files added?
    file_paths = jq(".[].data.path").transform(events, multiple_output=True)
    for name in range(n_regular):
        assert(os.path.join(folder, f'regular_{name}') in file_paths)

    # Modify previous text files
    for name in range(n_regular):
        with open(os.path.join(folder, f'regular_{name}'), 'a') as f:
            f.write('new content')

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=max(n_regular * 0.01, min_timeout), callback=callback_detect_event,
                                    accum_results=n_regular).result()

    # Are the n_regular events of type 'modified'?
    types = Counter(jq(".[].data.type").transform(events, multiple_output=True))
    assert (types['modified'] == n_regular)

    # Are the n_regular events the files modified?
    file_paths = jq(".[].data.path").transform(events, multiple_output=True)
    for name in range(n_regular):
        assert (os.path.join(folder, f'regular_{name}') in file_paths)

    # Delete previous text files
    for name in range(n_regular):
        os.remove(os.path.join(folder, f'regular_{name}'))

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=max(n_regular * 0.01, min_timeout), callback=callback_detect_event,
                                    accum_results=n_regular).result()

    # Are the n_regular events of type 'deleted'?
    types = Counter(jq(".[].data.type").transform(events, multiple_output=True))
    assert (types['deleted'] == n_regular)

    # Are the n_regular events the files modified?
    file_paths = jq(".[].data.path").transform(events, multiple_output=True)
    for name in range(n_regular):
        assert (os.path.join(folder, f'regular_{name}') in file_paths)
