# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
from collections import Counter

import pytest
from jq import jq

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1')]
testdir1 = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.benchmark
@pytest.mark.parametrize('n_regular, folder', [
    (10, testdir1),
    (100, testdir1),
    (1000, testdir1),
    (10000, testdir1)
])
def test_benchmark_regular_files(n_regular, folder, configure_environment, restart_wazuh):
    """Checks syscheckd detects a minimum volume of file changes (add, modify, delete)"""

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
