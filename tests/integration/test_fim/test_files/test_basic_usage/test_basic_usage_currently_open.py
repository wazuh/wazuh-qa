'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM could work correctly when a file is open.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
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
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import generate_params, callback_detect_integrity_event
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import write_file_without_close, remove_file
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import PREFIX


# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]


# variables

directory_str = os.path.join(PREFIX, 'testdir')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_conf.yaml')


# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
parameters, metadata = generate_params(extra_params=conf_params, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('tags_to_apply', [{'ossec_conf'}])
def test_file_currently_open(tags_to_apply, get_configuration, configure_environment, file_monitoring,
                             restart_syscheckd):
    '''
    description: Check if FIM could work correctly when a file is open..
                 For this purpose, the test open a file without close and restart Wazuh
                 in order to get the first scan of FIM. Finally, it verifies that
                 the FIM events have been generated properly.

    wazuh_min_version: 4.1.3

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that FIM events are generated for the operations performed.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_basic_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending integrity control message: (.+)$' (Sending integrity control when restarting Wazuh)

    tags:
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Created and writre file without close
    write_file_without_close(directory_str, directory_str)

    # Restart Wazuh and check FIM logs
    try:
        # File integrity monitoring scan
        control_service('restart')
        log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_integrity_event,
                          error_message='Did not receive expected '
                          '"Sending integrity control message: ..." event')

    # Delete directory
    finally:
        remove_file(directory_str)
