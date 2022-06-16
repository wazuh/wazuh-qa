'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM updates the target of 'symbolic links'
       when it is changed.
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
import os

import pytest
import wazuh_testing.fim as fim

from test_fim.test_files.test_follow_symbolic_link.common import configurations_path, testdir1, \
    modify_symlink, testdir_link, wait_for_symlink_check, testdir_target, testdir_not_target
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_after_yield, \
    extra_configuration_before_yield
from wazuh_testing import logger
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# All tests in this module apply to linux only
pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]
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

@pytest.mark.parametrize('tags_to_apply, main_folder, aux_folder', [
    ({'monitored_file'}, testdir1, testdir_not_target),
    ({'monitored_dir'}, testdir_target, testdir_not_target)
])
def test_symbolic_change_target(tags_to_apply, main_folder, aux_folder, get_configuration, configure_environment,
                                restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' updates the symlink target properly. For this purpose,
                 the test will monitor a 'symbolic link' pointing to a file/directory. Once FIM starts,
                 it will create and expect events inside the pointed folder. Then, it will create files
                 inside the new target, making sure that it will not generate any events. After
                 the FIM events are processed, the test will change the target of the link to another
                 folder and wait until the thread that checks the symbolic links updates the target.
                 Finally, the test will check if the new file is being monitored and the old one is not.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - main_folder:
            type: str
            brief: Directory that is being pointed at or contains the pointed file.
        - aux_folder:
            type: str
            brief: Directory that will be pointed at or will contain the future pointed file.
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
        - Verify that FIM events are generated at the initial target of the 'symbolic link'.
        - Verify that no FIM events are generated in the final target before changing it in the 'symbolic link'.
        - Verify that no FIM events are generated in the initial target of the 'symbolic link'
          when it has already been changed to the final target.

    input_description: Two test cases (monitored_file and monitored_dir) are contained in external YAML file
                       (wazuh_conf.yaml) which includes configuration settings for the 'wazuh-syscheckd' daemon
                       and, these are combined with the testing directories to be monitored defined in
                       the 'common.py' module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' and 'modified' events)

    tags:
        - scheduled
        - time_travel
    '''
    def modify_and_check_events(f1, f2, text):
        """
        Modify the content of 2 given files. We assume the first one is being monitored and the other one is not.
        We expect a 'modified' event for the first one and a timeout for the second one.
        """
        fim.modify_file_content(f1, file1, text)
        fim.modify_file_content(f2, file1, text)
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        modify = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event,
                                         error_message='Did not receive expected "Sending FIM event: ..." event'
                                         ).result()
        assert 'modified' in modify['data']['type'] and f1 in modify['data']['path'], \
            f"'modified' event not matching for {file1}"
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=3, callback=fim.callback_detect_event)
            logger.error(f'Unexpected event {event.result()}')
            raise AttributeError(f'Unexpected event {event.result()}')

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'
    file1 = 'regular1'

    # If symlink is pointing to a directory, we need to add files and expect their 'added' event (only if the file
    # is being created withing the pointed directory
    if main_folder == testdir_target:
        fim.create_file(fim.REGULAR, main_folder, file1, content='')
        fim.create_file(fim.REGULAR, aux_folder, file1, content='')
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        add = wazuh_log_monitor.start(timeout=10, callback=fim.callback_detect_event,
                                      error_message='Did not receive expected "Sending FIM event: ..." event'
                                      ).result()
        assert 'added' in add['data']['type'] and file1 in add['data']['path'], \
            f"'added' event not matching for {file1}"
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=10, callback=fim.callback_detect_event)
            logger.error(f'Unexpected event {event.result()}')
            raise AttributeError(f'Unexpected event {event.result()}')
    else:
        fim.create_file(fim.REGULAR, aux_folder, file1, content='')
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=10, callback=fim.callback_detect_event)
            logger.error(f'Unexpected event {event.result()}')
            raise AttributeError(f'Unexpected event {event.result()}')

    # Change the target of the symlink and expect events while there's no syscheck scan
    # Don't expect events from the new target
    if tags_to_apply == {'monitored_dir'}:
        modify_symlink(aux_folder, os.path.join(testdir_link, 'symlink2'))
    else:
        modify_symlink(aux_folder, os.path.join(testdir_link, 'symlink'), file=file1)
    modify_and_check_events(main_folder, aux_folder, 'Sample number one')

    wait_for_symlink_check(wazuh_log_monitor)
    fim.wait_for_audit(whodata, wazuh_log_monitor)

    # Expect events the other way around now
    modify_and_check_events(aux_folder, main_folder, 'Sample number two')
