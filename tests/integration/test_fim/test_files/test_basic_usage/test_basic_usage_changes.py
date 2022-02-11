'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. In particular, these tests will check if common operations
       ('add', 'modify', and 'delete') on monitored directories are correctly detected.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 0

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows
    - macos
    - solaris

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
    - macOS Catalina
    - Solaris 10
    - Solaris 11

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
    - fim_basic_usage
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import CHECK_ALL, LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories + [os.path.join(PREFIX, 'noexists')])
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('name, encoding, checkers,  tags_to_apply', [
    ('regular0', None, {CHECK_ALL}, {'ossec_conf'}),
    pytest.param('檔案', 'cp950', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                    pytest.mark.darwin,
                                                                    pytest.mark.sunos5)),
    pytest.param('Образецтекста', 'koi8-r', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                                pytest.mark.darwin,
                                                                                pytest.mark.sunos5)),
    pytest.param('Δείγμακειμένου', 'cp737', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                                pytest.mark.darwin,
                                                                                pytest.mark.sunos5)),
    pytest.param('نصبسيط', 'cp720', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                        pytest.mark.darwin,
                                                                        pytest.mark.sunos5)),
    pytest.param('Ξ³ΞµΞΉΞ±', None, {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.win32,
                                                                       pytest.mark.xfail(reason='Xfail due to issue: \
                                                                       https://github.com/wazuh/wazuh/issues/4612')))
])
def test_regular_file_changes(folder, name, encoding, checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects regular file changes (add, modify, delete).
                 For this purpose, the test uses different character encodings in the names of the testing
                 directories and files and performs operations on them. Finally, it verifies that
                 the FIM events have been generated properly.

    wazuh_min_version: 4.2.0

    parameters:
        - folder:
            type: str
            brief: Path to the monitored testing directory.
        - name:
            type: str
            brief: Name used for the testing files.
        - encoding:
            type: str
            brief: Character encoding used for the directory and testing files.
        - checkers:
            type: dict
            brief: Syscheck checkers (check_all).
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
        - Verify that all FIM events are generated for the operations performed,
          and these contain all 'check_' fields specified in the configuration.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple FIM events logs of the monitored directories.

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    mult = 1 if sys.platform == 'win32' else 2

    if encoding is not None:
        name = name.encode(encoding)
        folder = folder.encode(encoding)

    regular_file_cud(folder, wazuh_log_monitor, file_list=[name],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout * mult, options=checkers, encoding=encoding,
                     triggers_event=True)
