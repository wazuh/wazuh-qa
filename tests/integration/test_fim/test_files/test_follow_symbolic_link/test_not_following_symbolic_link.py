'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM stops monitoring
       the target of a 'symbolic_link' found in the monitored directory when the attribute
       'follow_symbolic_link' is disabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

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
import os

import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import modify_symlink
from wazuh_testing import global_parameters, logger
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir_link'), os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2')]
testdir_link, testdir1, testdir2 = test_directories

wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'yes'})
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('monitored_dir, non_monitored_dir1, non_monitored_dir2, sym_target, tags_to_apply', [
    (testdir_link, testdir1, testdir2, 'file', {'non_monitored_dir'}),
    (testdir_link, testdir1, testdir2, 'folder', {'non_monitored_dir'})
])
def test_symbolic_monitor_directory_with_symlink(monitored_dir, non_monitored_dir1, non_monitored_dir2,
                                                 sym_target, tags_to_apply, get_configuration, configure_environment,
                                                 restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events when monitoring a directory with a symlink and
                 not the symlink itself. For this purpose, the test will create some files in a non-monitored folder
                 and will not expect any events. Then, it will create a 'symbolic link' inside the monitored folder
                 pointing to the non-monitored folder. The test will expect an FIM 'added' event with the path
                 of the 'symbolic link', as it is within a monitored directory. It will create some events in
                 the link target and will not expect any events. Finally, the test will change the link target,
                 and it will expect an FIM 'modified' event.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - monitored_dir:
            type: str
            brief: Directory that is being monitored.
        - non_monitored_dir1:
            type: str
            brief: Directory that is being monitored.
        - non_monitored_dir2:
            type: str
            brief: Directory that is being monitored.
        - sym_target:
            type: str
            brief: Path to the target of the 'symbolic link'.
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
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
        - Verify that no FIM events are generated when performing file operations
          on a 'symbolic link' target in a monitored directory.
        - Verify that FIM events are generated when adding or modifying the 'symbolic link' itself.

    input_description: A test case (non_monitored_dir) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    name1 = f'{sym_target}regular1'
    name2 = f'{sym_target}regular2'
    sl_name = f'{sym_target}symlink'
    a_path = os.path.join(non_monitored_dir1, name1)
    b_path = os.path.join(non_monitored_dir1, name2) if sym_target == 'file' else non_monitored_dir2
    sl_path = os.path.join(monitored_dir, sl_name)
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Create regular files out of the monitored directory and don't expect its event
    fim.create_file(fim.REGULAR, non_monitored_dir1, name1, content='')
    fim.create_file(fim.REGULAR, non_monitored_dir1, name2, content='')
    target = a_path if sym_target == 'file' else non_monitored_dir1
    fim.create_file(fim.SYMLINK, monitored_dir, sl_name, target=target)

    # Create the symlink and expect its event, since it's withing the monitored directory
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event')

    # Modify the target file and don't expect any event
    fim.modify_file(non_monitored_dir1, name1, new_content='Modify sample')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=5, callback=fim.callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')

    # Modify the target of the symlink and expect the modify event
    modify_symlink(target=b_path, path=sl_path)
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                     error_message='Did not receive expected '
                                                   '"Sending FIM event: ..." event').result()
    if 'modified' in result['data']['type']:
        logger.info("Received modified event. No more events will be expected.")
    elif 'deleted' in result['data']['type']:
        logger.info("Received deleted event. Now an added event will be expected.")
        result = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event').result()
        assert 'added' in result['data']['type'], f"The event {result} should be of type 'added'"
    else:
        assert False, f"Detected event {result} should be of type 'modified' or 'deleted'"

    # Remove and restore the target file. Don't expect any events
    fim.delete_file(b_path, name2)
    fim.create_file(fim.REGULAR, non_monitored_dir1, name2, content='')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        event = wazuh_log_monitor.start(timeout=5, callback=fim.callback_detect_event)
        logger.error(f'Unexpected event {event.result()}')
        raise AttributeError(f'Unexpected event {event.result()}')
