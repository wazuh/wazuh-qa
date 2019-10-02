# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from datetime import timedelta

import pytest

from wazuh_testing.fim import *
from wazuh_testing.tools import (FileMonitor, TimeMachine, check_apply_test,
                                 load_wazuh_configurations, set_section_wazuh_conf)


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

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply, new_ossec_conf', [
    ({'schedule_report'}, set_section_wazuh_conf(configurations[3].get('section'),
                                                 configurations[3].get('elements'))),
    ({'realtime_report'}, set_section_wazuh_conf(configurations[4].get('section'),
                                                 configurations[4].get('elements'))),
    ({'whodata_report'}, set_section_wazuh_conf(configurations[5].get('section'),
                                                configurations[5].get('elements'))),
])
@pytest.mark.parametrize('folder, checkers, no_diff', [
    (testdir_reports, options, False),
])
def test_reports_file_and_nodiff(folder, checkers, no_diff, tags_to_apply, new_ossec_conf,
                                 get_configuration, configure_environment,
                                 restart_wazuh, wait_for_initial_scan):

    check_apply_test(tags_to_apply, get_configuration['tags'])

    filename = 'regularfile'

    # Check if a diff file is created
    create_file(REGULAR, filename, folder, 'Sample content')
    if tags_to_apply == {'schedule_report'}:
        TimeMachine.travel_to_future(timedelta(hours=13))
    # Check if file is duplicated
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local',
                             folder.strip('/'), filename)
    # Wait until event is detected
    wazuh_log_monitor.start(timeout=3, callback=callback_detect_event)

    assert (os.path.exists(diff_file))
    # Restart Wazuh without report_changes
    restart_wazuh_with_new_conf(new_ossec_conf, wazuh_log_monitor)
    assert(os.path.exists(diff_file) is False)

#
# @pytest.fixture(scope='function', params=glob.glob(os.path.join(test_data_path, 'ossec_delete.conf')))
# def get_ossec_configuration_report(request):
#     return request.param
#
# @pytest.fixture(scope='function')
# def configure_environment_report(get_ossec_configuration_report, request):
#     # Place configuration in path
#     shutil.copy(get_ossec_configuration_report, WAZUH_CONF_PATH)
#     shutil.chown(WAZUH_CONF_PATH, 'root', 'ossec')
#     os.chmod(WAZUH_CONF_PATH, mode=0o660)
#
#     yield
#     # Remove created folders
#     for test_dir in test_directories:
#         shutil.rmtree(test_dir, ignore_errors=True)
#
# @pytest.fixture(scope='function')
# def wait_for_initial_scan_report(get_ossec_configuration_report, request):
#     # Wait for initial FIM scan to end
#     file_monitor = getattr(request.module, 'wazuh_log_monitor')
#     file_monitor.start(timeout=60, callback=callback_detect_end_scan)
#
#     # Add additional sleep to avoid changing system clock issues (TO BE REMOVED when syscheck has not sleeps anymore)
#     time.sleep(11)
#
# @pytest.fixture(scope='function')
# def restart_wazuh_report(get_ossec_configuration_report, request):
#     # Reset ossec.log and start a new monitor
#     truncate_file(LOG_FILE_PATH)
#     file_monitor = FileMonitor(LOG_FILE_PATH)
#     setattr(request.module, 'wazuh_log_monitor', file_monitor)
#
#     # Restart Wazuh and wait for the command to end
#     p = subprocess.Popen(["service", "wazuh-manager", "restart"])
#     p.wait()

# @pytest.mark.parametrize('folder, name, filetype, content', [(testdir_nodiff, 'file', REGULAR, 'Sample content')])
# def _test_delete_diff_deletion(folder, name, filetype, content, configure_environment_report, restart_wazuh_report, wait_for_initial_scan_report):
#     # Check if the diff file is deleted
#     diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local', folder[1:], name, 'last-entry.gz')
#     print(f'diff file path: {diff_file}')
#     assert (os.path.isfile(diff_file) == False)
