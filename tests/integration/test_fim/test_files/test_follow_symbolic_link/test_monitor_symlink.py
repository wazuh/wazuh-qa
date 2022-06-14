'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM generates events when monitoring
       a 'symbolic link' that points to a file or a directory.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files for
       changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_follow_symbolic_link

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - macos
    - solaris

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_follow_symbolic_link
'''
import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    testdir_target, delete_f
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
    extra_configuration_after_yield
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'})
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply, main_folder', [
    ({'monitored_file'}, testdir1),
    ({'monitored_dir'}, testdir_target)
])
def test_symbolic_monitor_symlink(tags_to_apply, main_folder, get_configuration, configure_environment,
                                  restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when monitoring a symlink that points
                 to a file or a directory. For this purpose, the test will monitor a 'symbolic link' pointing
                 to a file/directory. Once FIM starts, if the link is a folder, creates a file and checks if
                 the expected FIM 'added' event is raised. Then, it will modify the link target and expect
                 the 'modified' event. Finally, the test will remove the link target and verify that
                 the FIM 'delete' event is generated.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - main_folder:
            type: str
            brief: Directory that is being pointed at or contains the pointed file.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are generated when performing file operations on a 'symbolic link' target.

    input_description: Two test cases (monitored_file and monitored_dir) are contained in external YAML file
                       (wazuh_conf.yaml) which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, these are combined with the testing directories to be monitored defined in
                       the 'common.py' module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file1 = 'regular1'

    # Add creation if symlink is pointing to a folder
    if tags_to_apply == {'monitored_dir'}:
        fim.create_file(fim.REGULAR, main_folder, file1, content='')
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        add = wazuh_log_monitor.start(timeout=10, callback=fim.callback_detect_event).result()
        assert 'added' in add['data']['type'] and file1 in add['data']['path'], \
            "'added' event not matching"

    # Modify the linked file and expect an event
    fim.modify_file_content(main_folder, file1, 'Sample modification')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    modify = wazuh_log_monitor.start(timeout=10, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    assert 'modified' in modify['data']['type'] and file1 in modify['data']['path'], \
        "'modified' event not matching"

    # Delete the linked file and expect an event
    delete_f(main_folder, file1)
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    delete = wazuh_log_monitor.start(timeout=10, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    assert 'deleted' in delete['data']['type'] and file1 in delete['data']['path'], \
        "'deleted' event not matching"
