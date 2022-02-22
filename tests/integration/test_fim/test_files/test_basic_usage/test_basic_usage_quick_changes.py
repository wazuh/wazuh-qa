'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM events of type 'added', 'modified',
       and 'deleted' are generated when the related operations are performed in specific time intervals.
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
    - fim_basic_usage
'''
import os
import time

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, \
    modify_file, delete_file, callback_detect_event, validate_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# variables

test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('sleep, tags_to_apply', [
    (0.25, {'ossec_conf'}),
    (0.5, {'ossec_conf'}),
    (0.75, {'ossec_conf'}),
    (1, {'ossec_conf'}),
    (1.25, {'ossec_conf'}),
    (1.50, {'ossec_conf'}),
    (1.75, {'ossec_conf'}),
    (2, {'ossec_conf'})
])
def test_regular_file_changes(sleep, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                              wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' regular file changes (add, modify, delete) with a very specific delay
                 between every operation. For this purpose, the test will perform the above operations over
                 a testing file and wait for the specified time between each operation. Finally, the test
                 will check that the  expected FIM events have been generated.

    wazuh_min_version: 4.2.0

    parameters:
        - sleep:
            type: float
            brief: Delay in seconds between every action.
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
        - Verify that FIM events of type 'added', 'modified', and 'deleted' are generated
          when the related operations are performed in specific time intervals.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$'

    tags:
        - realtime
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file = 'regular'
    create_file(REGULAR, path=testdir1, name=file, content='')
    time.sleep(sleep)
    modify_file(path=testdir1, name=file, new_content='Sample')
    time.sleep(sleep)
    delete_file(path=testdir1, name=file)

    try:
        events = wazuh_log_monitor.start(timeout=max(sleep * 3, global_parameters.default_timeout),
                                         callback=callback_detect_event, accum_results=3,
                                         error_message='Did not receive expected '
                                                       '"Sending FIM event: ..." event').result()
        for ev in events:
            validate_event(ev)
    except TimeoutError as e:
        if get_configuration['metadata']['fim_mode'] == 'whodata':
            pytest.xfail(reason='Xfailing due to issue: https://github.com/wazuh/wazuh/issues/4710')
        else:
            raise e
