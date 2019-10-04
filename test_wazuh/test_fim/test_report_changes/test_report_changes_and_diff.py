# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH, regular_file_cud)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [
    os.path.join('/', 'testdir_reports'),
    os.path.join('/', 'testdir_nodiff')
]
testdir_reports, testdir_nodiff = test_directories
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': '',
                                                    'REPORT_CHANGES': {'report_changes': 'yes'},
                                                    'MODULE_NAME': __name__},
                                                   {'FIM_MODE': {'realtime': 'yes'},
                                                    'REPORT_CHANGES': {'report_changes': 'yes'},
                                                    'MODULE_NAME': __name__},
                                                   {'FIM_MODE': {'whodata': 'yes'},
                                                    'REPORT_CHANGES': {'report_changes': 'yes'},
                                                    'MODULE_NAME': __name__}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled', 'report_changes': True,
                                                      'module_name': __name__},
                                                     {'fim_mode': 'realtime', 'report_changes': True,
                                                      'module_name': __name__},
                                                     {'fim_mode': 'whodata', 'report_changes': True,
                                                      'module_name': __name__}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_report'}
])
@pytest.mark.parametrize('folder, checkers', [
    (testdir_reports, options),
    (testdir_nodiff, options)
])
def test_reports_file_and_nodiff(folder, checkers, tags_to_apply,
                                 get_configuration, configure_environment,
                                 restart_wazuh, wait_for_initial_scan):
    """ Check if report_changes events and diff truncated files are correct  """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    # More than one regular file will make the test fail
    min_timeout = 3
    time_travel = False
    rc = get_configuration['metadata']['report_changes']
    nd = folder == testdir_nodiff
    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        time_travel = True
    regular_file_cud(folder, wazuh_log_monitor, time_travel, 1, min_timeout, options=checkers,
                     report_changes=rc, no_diff=nd)
