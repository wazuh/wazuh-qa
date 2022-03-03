'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these files
       are modified. Specifically, these tests will check if FIM stops monitoring the target of
       a 'symbolic_link' when the attribute 'follow_symbolic_link' is disabled.
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
from test_fim.test_files.test_follow_symbolic_link.common import testdir_target, testdir1
# noinspection PyUnresolvedReferences
from test_fim.test_files.test_follow_symbolic_link.common import test_directories, extra_configuration_before_yield, \
     extra_configuration_after_yield
from wazuh_testing import logger
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.sunos5, pytest.mark.darwin, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(fim.LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = fim.generate_params(extra_params={'FOLLOW_MODE': 'no'})
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

@pytest.mark.parametrize('tags_to_apply, path', [
    ({'monitored_file'}, testdir1),
    ({'monitored_dir'}, testdir_target)
])
def test_follow_symbolic_disabled(path, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                  wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon considers a 'symbolic link' to be a regular file when
                 the attribute 'follow_symbolic_link' is set to 'no'. For this purpose, the test will monitor
                 a 'symbolic link' pointing to a file/directory. Once FIM starts, it will create and not expect
                 events inside the pointed folder. Then, the test will modify the link target and check that
                 no events are triggered. Finally, it will remove the link target and verify that no FIM events
                 have been generated.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - path:
            type: str
            brief: Path to the target file or directory.
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
        - Verify that no FIM events are generated when performing file operations on a 'symbolic link' target.

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
    regular_file = 'regular1'
    error_msg = 'A "Sending FIM event: ..." event has been detected. No events should be detected at this time.'

    # If the symlink targets to a directory, create a file in it and ensure no event is raised.
    if tags_to_apply == {'monitored_dir'}:
        fim.create_file(fim.REGULAR, path, regular_file)
        fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=5, callback=fim.callback_detect_event)
            logger.error(error_msg)
            raise AttributeError(error_msg)

    # Modify the target file and don't expect any events
    fim.modify_file(path, regular_file, new_content='Modify sample')
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=fim.callback_detect_event)
        logger.error(error_msg)
        raise AttributeError(error_msg)

    # Delete the target file and don't expect any events
    fim.delete_file(path, regular_file)
    fim.check_time_travel(scheduled, monitor=wazuh_log_monitor)
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=5, callback=fim.callback_detect_event)
        logger.error(error_msg)
        raise AttributeError(error_msg)
