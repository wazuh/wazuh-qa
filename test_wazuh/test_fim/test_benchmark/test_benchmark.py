# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
from collections import Counter

import pytest
from jq import jq

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, regular_file_cud
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1')]
testdir1 = test_directories[0]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.benchmark
@pytest.mark.parametrize('applies_to_config', [
    'ossec_realtime.conf',
    'ossec_whodata.conf'
])
@pytest.mark.parametrize('n_regular, folder, is_scheduled', [
    (10, testdir1, False),
    (100, testdir1, False),
    (1000, testdir1, False),
    (10000, testdir1, False)
])
def test_benchmark_regular_files(n_regular, folder, is_scheduled, applies_to_config, configure_environment, restart_wazuh, wait_for_initial_scan):
    """Checks syscheckd detects a minimum volume of file changes (add, modify, delete)"""

    min_timeout = 30

    regular_file_cud(folder, is_scheduled, n_regular, min_timeout, wazuh_log_monitor)
