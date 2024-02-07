'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events generated contain only
       the 'check_' fields specified in the configuration when using the 'check_all' attribute along
       with other 'check_' attributes.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: file_checks

targets:
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
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

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
    - test_file_checkers
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import CHECK_GROUP, CHECK_MTIME, CHECK_OWNER, CHECK_PERM, \
    CHECK_SHA256SUM, CHECK_SIZE, CHECK_MD5SUM, CHECK_SHA1SUM, CHECK_ALL, \
    LOG_FILE_PATH, REQUIRED_ATTRIBUTES, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.utils import regular_file_cud
from wazuh_testing.tools import PREFIX
from time import sleep

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables

directory_1 = os.path.join(PREFIX, "testdirectory_1")
directory_2 = os.path.join(PREFIX, "testdirectory_2")
directory_3 = os.path.join(PREFIX, "testdirectory_3")
directory_4 = os.path.join(PREFIX, "testdirectory_4")
directory_5 = os.path.join(PREFIX, "testdirectory_5")

test_folders = [directory_1,
                directory_2,
                directory_3,
                directory_4,
                directory_5,
                ]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

file_all_attrs = REQUIRED_ATTRIBUTES[CHECK_ALL]

file_attrs_no_hash_sha1 = file_all_attrs - {CHECK_SHA1SUM}
file_attrs_no_hash_md5 = file_all_attrs - {CHECK_MD5SUM}
file_attrs_no_hash_sha256 = file_all_attrs - {CHECK_SHA256SUM}
file_attrs_no_size = file_all_attrs - {CHECK_SIZE}
file_attrs_no_mtime = file_all_attrs - {CHECK_MTIME}


# Configurations

conf_params = {'DIRECTORY_1': test_folders[0],
               'DIRECTORY_2': test_folders[1],
               'DIRECTORY_3': test_folders[2],
               'DIRECTORY_4': test_folders[3],
               'DIRECTORY_5': test_folders[4],
               }

configurations_path = os.path.join(test_data_path, 'wazuh_check_all.yaml')
p, m = generate_params(extra_params=conf_params, modes=['realtime'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('test_folders', [test_folders], ids='', scope='module')
@pytest.mark.parametrize('file_path, file_attrs, tags_to_apply, triggers_modification', [
    (directory_1, file_all_attrs, {'check_all_yes'}, True),
    (directory_1, set(), {'check_all_no'}, False),
    (directory_1, file_attrs_no_hash_sha1, {'check_just_one_no'}, True),
    (directory_2, file_attrs_no_hash_md5, {'check_just_one_no'}, True),
    (directory_3, file_attrs_no_hash_sha256, {'check_just_one_no'}, True),
    (directory_4, file_attrs_no_size, {'check_just_one_no'}, True),
    (directory_5, file_attrs_no_mtime, {'check_just_one_no'}, True),
    (directory_1, {CHECK_SHA1SUM}, {'check_just_one_yes'}, True),
    (directory_2, {CHECK_MD5SUM}, {'check_just_one_yes'}, True),
    (directory_3, [CHECK_SHA256SUM], {'check_just_one_yes'}, True),
    (directory_4, {CHECK_SIZE}, {'check_just_one_yes'}, True),
    (directory_5, {CHECK_MTIME}, {'check_just_one_yes'}, True),
])
def test_checkers(file_path, file_attrs, tags_to_apply, triggers_modification, create_monitored_folders_module,
                  test_folders, get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon adds in the generated events the 'check_' specified in
                 the configuration. These checks are attributes indicating that a monitored directory entry has
                 been modified. For example, if 'check_all=yes' and 'check_perm=no' are set for the same entry,
                 'syscheck' must send an event containing every possible 'check_' except the perms.
                 For this purpose, the test will monitor a directory using the 'check_all' attribute in
                 conjunction with one or more 'check_' on the same directory, having 'check_all' to 'yes' and the other
                 one to 'no'. Then it will make directory operations inside it, and finally, the test
                 will verify that the FIM events generated contain only the fields of the 'checks' specified for
                 the monitored keys/values.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - file_path:
            type: str
            brief: Path of the directory that will be created under the root directory.
        - file_attrs:
            type: set
            brief: Set of options that are expected for directory events.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - triggers_modification:
            type: bool
            brief: Specify if the given options generate file events.
        - create_monitored_folders_module:
            type: fixture
            brief: Create a given list of folders when the module starts. Delete the folders at the end of the module.
        - test_folders:
            type: dict
            brief: List of folders to be created for monitoring.
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
        - Verify that the FIM events generated contain only the 'check_' fields specified in the configuration.

    input_description: Different test cases are contained in an external YAML file (wazuh_check_all.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. Those are
                       combined with the testing directories to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - realtime
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    def waitasecond(event):
        sleep(1)

    # In the case of CHECK_MTIME only, we need to wait one second after file creation for the timestamp to be different
    # (otherwise FIM will not generate alert).
    if file_attrs == {CHECK_MTIME}:
        regular_file_cud(file_path, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                         validators_after_create=[waitasecond],
                         options=file_attrs, triggers_modified_event=triggers_modification, escaped=True)
    # Test files checks.
    else:
        regular_file_cud(file_path, wazuh_log_monitor, min_timeout=global_parameters.default_timeout,
                         options=file_attrs, triggers_modified_event=triggers_modification, escaped=True)
