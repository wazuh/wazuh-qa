'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. All these tests will be performed using ambiguous directory configurations,
       such as directories and subdirectories with opposite monitoring settings. In particular, it
       will be tested that changes in the files are correctly detected through their properties.
       Several monitoring attribute are also tested, such as recursion level, file restrictions, tags,
       or changes reporting.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_ambiguous_confs
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, regular_file_cud, WAZUH_PATH,
                               CHECK_ALL, CHECK_GROUP, CHECK_INODE,
                               CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA256SUM,
                               CHECK_SIZE, CHECK_SUM, REQUIRED_ATTRIBUTES, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(
    test_data_path, 'wazuh_conf_simple_win32.yaml' if sys.platform == 'win32' else 'wazuh_conf_simple.yaml')
checkdir_default = os.path.join(PREFIX, 'checkdir_default')
checkdir_checkall = os.path.join(checkdir_default, 'checkdir_checkall')
checkdir_no_inode = os.path.join(checkdir_checkall, 'checkdir_no_inode')
checkdir_no_checksum = os.path.join(checkdir_no_inode, 'checkdir_no_checksum')
test_directories = [os.path.join(PREFIX, 'testdir'), os.path.join(PREFIX, 'testdir', 'subdir'),
                    os.path.join(PREFIX, 'recursiondir'), os.path.join(PREFIX, 'recursiondir_tag'),
                    os.path.join(PREFIX, 'recursiondir_no_tag'), checkdir_default, checkdir_checkall,
                    checkdir_no_inode, checkdir_no_checksum]
testdir, subdir = test_directories[0:2]
testdir_recursion = test_directories[2]
testdir_recursion_tag = test_directories[3]
testdir_recursion_no_tag = test_directories[4]

check_list = {CHECK_SIZE} | {CHECK_PERM} | {CHECK_OWNER} | {CHECK_GROUP} | {CHECK_SHA256SUM} | {CHECK_MTIME}
if sys.platform != 'win32':
    check_list = check_list | {CHECK_INODE}
parametrize_list = [(checkdir_default, check_list),
                    (checkdir_checkall, REQUIRED_ATTRIBUTES[CHECK_ALL]),
                    (checkdir_no_inode, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE}),
                    (checkdir_no_checksum, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM])
                    ]

tag = 'Sample_tag'

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'TAGS': tag})
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions

def tag_validator(event):
    """Validate tags event property exists in the event."""
    assert tag == event['data']['tags'], 'defined_tags are not equal'


def no_tag_validator(event):
    """Validate tags event property does not exist in the event."""
    assert 'tags' not in event['data'].keys(), "'tags' key found in event"


def _test_recursion_cud(ini, fin, path, recursion_subdir, scheduled,
                        min_timeout, triggers_event, validators_after_cud=None):
    """Apply `regular_file_cud` on different recursion levels.

    Iterate from `ini` recursion level to `fin` recursion level, creating the
    corresponding subdirectory and applying the `regular_file_cud` function on it.

    Parameters
    ----------
    ini : int
        Initial level of recursion.
    fin : int
        Final level of recursion.
    path : string
        Path over which subdirectories will be created.
    recursion_subdir : string
        Name for subdirectories.
    scheduled : bool
        Determine if there will be time travels or not
    min_timeout : int
        Minimum timeout
    triggers_event : bool
        determine if the event should be raised or not.
    validators_after_cud : list, optional
        functions that validate an event triggered when a new file is created, modified
    or deleted. Each function must accept a param to receive the event to be validated.

    Returns
    -------
    path : string
        Full path after adding all the subdirectories.
    """
    for n in range(ini, fin):
        path = os.path.join(path, recursion_subdir + str(n + 1))
        regular_file_cud(path, wazuh_log_monitor, time_travel=scheduled, min_timeout=min_timeout,
                         triggers_event=triggers_event, validators_after_cud=validators_after_cud)
    return path


# tests
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('folders, tags_to_apply', [
    ([testdir, subdir], {'ambiguous_restrict'})
])
def test_ambiguous_restrict(folders, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                            wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects regular file changes (add, modify, delete) depending
                 on the value set in the 'restrict' attribute. This attribute limit checks to files containing
                 the entered string in the file name.
                 For example, if '/testdir' has a 'restrict' configuration and '/testdir/subdir' has not,
                 only /testdir/subdir events should appear in the 'ossec.log'file.
                 For this purpose, the two previous paths are monitored, and modifications are made to the files
                 to check if alerts are generated when required.

    wazuh_min_version: 4.2.0

    parameters:
        - folders:
            type: list
            brief: Monitored directories.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that no alerts are generated after modifying files in the directory specified in the 'restrict' option.
        - Verify that alerts are generated after modifying files in the subdirectory that is not specified
          in the 'restrict' option, but whose parent directory is restricted.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf_simple.yaml or wazuh_conf_simple_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple logs of FIM events in the monitored directories.

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    file_list = ['example.csv']
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    regular_file_cud(folders[0], wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=False)

    regular_file_cud(folders[1], wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=True)

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('folders, tags_to_apply', [
    ([testdir, subdir], {'ambiguous_report_changes'})
])
def test_ambiguous_report(folders, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or not the 'content_changes' field for each event
                 depending on the value set in the 'report_changes' attribute. This attribute allows reporting
                 the modifications made on a monitored file. For this purpose, two folders are monitored,
                 and modifications are made to the files to check if the 'content_changes' field
                 is generated in the events when required.

    wazuh_min_version: 4.2.0

    parameters:
        - folders:
            type: list
            brief: Monitored directories.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that the 'content_changes' field is not generated in events when 'report_changes == no'.
        - Verify that the 'content_changes' field is generated in events when 'report_changes == yes'.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf_simple.yaml or wazuh_conf_simple_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple logs of FIM events in the monitored directories.

    tags:
        - scheduled
        - time_travel
    '''
    def report_changes_validator(event):
        """Validate content_changes event property exists in the event."""
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
            striped = folder.strip(os.sep) if sys.platform == 'darwin' else folder.strip(PREFIX)
            diff_file = os.path.join(diff_file, striped, file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    def no_report_changes_validator(event):
        """Validate content_changes event property does not exist in the event."""
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
            striped = folder.strip(os.sep) if sys.platform == 'darwin' else folder.strip(PREFIX)
            diff_file = os.path.join(diff_file, striped, file)

            assert not os.path.exists(diff_file), f'{diff_file} exists'
            assert 'content_changes' not in event['data'].keys(), f"'content_changes' in event"

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file_list = ['regular']
    folder = folders[1]

    # Check if create, update and delete events in folders[1] contain the field 'content_changes'.
    regular_file_cud(folders[1], wazuh_log_monitor, file_list=file_list, time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator])

    # Check if events in folders[0] do not contain the field 'content_changes'
    folder = folders[0]
    regular_file_cud(folders[0], wazuh_log_monitor, file_list=file_list, time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[no_report_changes_validator])

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('folders, tags_to_apply', [
    ([testdir, subdir], {'ambiguous_tags'})
])
def test_ambiguous_tags(folders, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                        wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects or not the 'tags' field for each event
                 depending on the value(s) set in the 'tags' attribute. This attribute allows adding
                 tags to alerts for monitored directories. For this purpose, two folders are monitored,
                 and modifications are made to the files to check if the 'tags' field is generated
                 in the events when required.

    wazuh_min_version: 4.2.0

    parameters:
        - folders:
            type: list
            brief: Monitored directories.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that the 'tags' field is not generated in events when the 'tags' attribute not exists or is empty.
        - Verify that the 'tags' field is generated in events when the 'tags' attribute has content.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf_simple.yaml or wazuh_conf_simple_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple logs of FIM events in the monitored directories.

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Check that events inside folder[0] do not contain the key 'tags'.
    regular_file_cud(folders[0], wazuh_log_monitor,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[no_tag_validator])

    # Check that events inside folder[1] do contain the key 'tags'.
    regular_file_cud(folders[1], wazuh_log_monitor,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[tag_validator])

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('dirname, recursion_level, tags_to_apply', [
    (testdir_recursion, 1, {'ambiguous_recursion_over'}),
    (testdir_recursion, 4, {'ambiguous_recursion'})
])
def test_ambiguous_recursion(dirname, recursion_level, tags_to_apply, get_configuration, configure_environment,
                             restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects alerts for each directory level defined in
                 the 'recursion_level' attribute. This attribute limits the maximum level of recursion allowed.
                 For example, if 'recursion_level=1' is set, and the '/testdir' directory is monitored,
                 it will only monitor '/testdir' and '/testdir/subdir'.
                 If '/testdir/subdir/subdir2' exists, '/subdir2' wouldn't be monitored.
                 For this purpose, a testing folder with several levels of subdirectories is monitored,
                 and modifications are made in each level to see if events are generated when required.

    wazuh_min_version: 4.2.0

    parameters:
        - dirname:
            type: string
            brief: Name of the monitored directory.
        - recursion_level:
            type: int
            brief: Value of the 'recursion_level' attribute.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that FIM events are generated up to the specified subdirectory depth.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf_simple.yaml or wazuh_conf_simple_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple logs of FIM events in the monitored directories.

    tags:
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    recursion_subdir = 'subdir'
    path = dirname

    # Iterate from ini to fin and verify that events are generated in the nested directories.
    path = _test_recursion_cud(ini=0, fin=recursion_level, path=path,
                               recursion_subdir=recursion_subdir,
                               scheduled=scheduled,
                               min_timeout=global_parameters.default_timeout, triggers_event=True)

    # Iterate from ini to fin and verify that events are NOT generated in nested directories
    # beyond the established recursion level.
    _test_recursion_cud(ini=recursion_level, fin=4, path=path,
                        recursion_subdir=recursion_subdir,
                        scheduled=scheduled,
                        min_timeout=global_parameters.default_timeout, triggers_event=False)

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('dirnames, recursion_level, triggers_event, tags_to_apply', [
    ([testdir_recursion_tag, testdir_recursion_no_tag], 2, True, {'ambiguous_recursion_tag'}),
    ([testdir_recursion_tag, testdir_recursion_no_tag], 2, False, {'ambiguous_no_recursion_tag'})
])
def test_ambiguous_recursion_tag(dirnames, recursion_level, triggers_event, tags_to_apply, get_configuration,
                                 configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects alerts for each directory level defined in
                 the 'recursion_level' attribute and if it detects the 'tags' field for each of them.
                 The 'tags' attribute allows adding tags to alerts for monitored directories,
                 and the 'recursion_level' attribute limits the maximum level of recursion allowed.
                 For this purpose, a testing folder with several levels of subdirectories is monitored,
                 and modifications are made in each level to see if events are generated when required.
                 Once the events have been generated, they are checked to see whether or not they
                 should include the 'tag' field.

    wazuh_min_version: 4.2.0

    parameters:
        - dirnames:
            type: list
            brief: Monitored directories.
        - recursion_level:
            type: int
            brief: Value of the 'recursion_level' attribute.
        - triggers_event:
            type: bool
            brief: Determine if the event should be raised or not.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that FIM events are generated up to the specified subdirectory depth.
        - Verify that the generated FIM events should or not contain the 'tag' field.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf_simple.yaml or wazuh_conf_simple_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple logs of FIM events in the monitored directories.

    tags:
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    recursion_subdir = 'subdir'

    # Iterate from ini to fin and verify that events generated in the nested directories contain the key 'tags'.
    _test_recursion_cud(ini=0, fin=recursion_level, path=dirnames[0],
                        recursion_subdir=recursion_subdir,
                        scheduled=scheduled, min_timeout=global_parameters.default_timeout,
                        triggers_event=triggers_event, validators_after_cud=[tag_validator])

    # Iterate from ini to fin and verify that events generated in the nested directories DO NOT contain the key 'tags'.
    _test_recursion_cud(ini=0, fin=recursion_level, path=dirnames[1],
                        recursion_subdir=recursion_subdir,
                        scheduled=scheduled, min_timeout=global_parameters.default_timeout,
                        triggers_event=triggers_event, validators_after_cud=[no_tag_validator])

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('tags_to_apply', [
    {'ambiguous_check'}
])
@pytest.mark.parametrize('dirname, checkers', parametrize_list)
def test_ambiguous_check(dirname, checkers, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                         wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects in the generated events the checks specified in
                 the configuration. These checks are attributes indicating that a monitored file has been modified.
                 For example, if 'check_all=yes' and 'check_inode=no' are set for the same directory, 'syscheck' must
                 send an event containing every possible check except the inode one.
                 For this purpose, different 'checks' are set in several subdirectories, and files are modified
                 to generate events. Finally, verification is performed to ensure that the events contain only
                 the fields of the 'checks' specified for the monitored folder.

    wazuh_min_version: 4.2.0

    parameters:
        - dirname:
            type: string
            brief: Name of the monitored directory.
        - checkers:
            type: set
            brief: Checks to be compared to the actual event check list (the one we get from the event).
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
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
        - Verify that the FIM events generated contain only the 'check' fields specified in the configuration.

    input_description: Different test cases are contained in external YAML files
                       (wazuh_conf_simple.yaml or wazuh_conf_simple_win32.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and testing
                       directories to monitor.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple logs of FIM events in the monitored directories.

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    regular_file_cud(dirname, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, options=checkers,
                     time_travel=scheduled)
