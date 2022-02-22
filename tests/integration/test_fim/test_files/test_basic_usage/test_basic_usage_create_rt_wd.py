'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. In particular, these tests will verify that only regular files are monitored
       using the 'realtime' and 'whodata' monitoring modes.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

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
from wazuh_testing.fim import (CHECK_ALL, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_event, create_file, validate_event, generate_params)
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

monitoring_modes = ['realtime', 'whodata']

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.xfail(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('name, filetype, content, checkers, tags_to_apply, encoding', [
    ('file', REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file2', REGULAR, b'Sample content', {CHECK_ALL}, {'ossec_conf'}, None),
    ('socketfile', REGULAR if sys.platform == 'win32' else SOCKET, '', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file3', REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}, None),
    ('fifofile', REGULAR if sys.platform == 'win32' else FIFO, '', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file4', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file-ñ', REGULAR, b'', {CHECK_ALL}, {'ossec_conf'}, None),
    pytest.param('檔案', REGULAR, b'', {CHECK_ALL}, {'ossec_conf'}, 'cp950', marks=(pytest.mark.linux,
                                                                                  pytest.mark.darwin,
                                                                                  pytest.mark.sunos5)),
    pytest.param('Образецтекста', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, 'koi8-r', marks=(pytest.mark.linux,
                                                                                             pytest.mark.darwin,
                                                                                             pytest.mark.sunos5)),
    pytest.param('Δείγμακειμένου', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, 'cp737', marks=(pytest.mark.linux,
                                                                                             pytest.mark.darwin,
                                                                                             pytest.mark.sunos5)),
    pytest.param('نصبسيط', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, 'cp720', marks=(pytest.mark.linux,
                                                                                     pytest.mark.darwin,
                                                                                     pytest.mark.sunos5)),
    pytest.param('Ξ³ΞµΞΉΞ±', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, None,
                 marks=(pytest.mark.win32,
                        pytest.mark.xfail(reason='Xfail due to issue: https://github.com/wazuh/wazuh/issues/4612')))
])
def test_create_file_realtime_whodata(folder, name, filetype, content, checkers, tags_to_apply, encoding,
                                      get_configuration,
                                      configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if a special or regular file creation is detected by the 'wazuh-syscheckd' daemon using
                 the 'realtime' and 'whodata' monitoring modes. Regular files must be monitored, special files
                 must not. For this purpose, the test creates the testing directories and files using different
                 character encodings in their names. Finally, it verifies that only the regular testing
                 files have generated FIM events.

    wazuh_min_version: 4.2.0

    parameters:
        - folder:
            type: str
            brief: Path to the monitored testing directory.
        - name:
            type: str
            brief: Name used for the testing file.
        - filetype:
            type: str
            brief: Type of the testing file.
        - content:
            type: str
            brief: Content of the testing file.
        - checkers:
            type: dict
            brief: Checks that will compared to the ones from the event.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - encoding:
            type: str
            brief: Character encoding used for the directory and testing files.
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
        - Verify that FIM events are only generated for the regular testing files,
          and these contain all 'check_' fields specified in the configuration.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple FIM events logs of the monitored directories.

    tags:
        - realtime
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files
    if encoding is not None:
        name = name.encode(encoding)
        folder = folder.encode(encoding)
    create_file(filetype, folder, name, content=content)

    if filetype == REGULAR:
        # Wait until event is detected
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                                        encoding=encoding, error_message='Did not receive expected '
                                                                         '"Sending FIM event: ..." event').result()
        validate_event(event, checkers)
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event)
            raise AttributeError(f'Unexpected event {event}')
