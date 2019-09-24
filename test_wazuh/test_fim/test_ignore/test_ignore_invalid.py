# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_configuration_error
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'wazuh_invalid*.conf')))
def get_ossec_configuration(request):
    return request.param


def test_ignore(get_ossec_configuration, configure_environment, restart_wazuh):
    """Checks if an invalid ignore configuration is detected
    """
    wazuh_log_monitor.start(timeout=3, callback=callback_configuration_error)
