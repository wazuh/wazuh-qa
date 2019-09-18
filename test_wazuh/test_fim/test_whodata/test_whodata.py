# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import glob
import pytest

from wazuh_testing.fim import callback_whodata_hc_success, callback_whodata_added_rule, LOG_FILE_PATH
from wazuh_testing.tools import TimeMachine, FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


def test_audit_health_check(configure_environment, restart_wazuh):
    """Checks if the health check is passed."""
    wazuh_log_monitor.start(timeout=20, callback=callback_whodata_hc_success)


def test_added_rules(configure_environment, restart_wazuh):
    """Checks if the specified folders are added to Audit rules list."""

    # Fetch the n_regular expected events
    events = wazuh_log_monitor.start(timeout=20, callback=callback_whodata_added_rule, accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)









