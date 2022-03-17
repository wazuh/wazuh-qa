'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if the 'wazuh-syscheckd' daemon generates
       a debug log when the 'directories' configuration tag is empty.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_basic_usage

targets:
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
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

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
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, callback_empty_directories
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=0)

# Variables

test_directories = []
testdir = os.path.join(PREFIX, 'testdir1')
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# Configurations

p, m = generate_params(extra_params={'TEST_DIRECTORIES': '', 'MODULE_NAME': __name__})
configuration1 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

p, m = generate_params(extra_params={'TEST_DIRECTORIES': testdir, 'MODULE_NAME': __name__})
configuration2 = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Merge both list of configurations into the final one to avoid skips and configuration issues
configurations = configuration1 + configuration2


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
def test_new_directory(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon shows a debug message when an empty 'directories' tag is found.
                 For this purpose, the test uses a configuration without specifying the directory to monitor.
                 It will then verify that the appropriate debug message is generated. Finally, the test will use
                 a valid directory and verify that the above message is not generated.

    wazuh_min_version: 4.2.0

    tier: 0

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
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the 'wazuh-syscheckd' daemon generates a debug log when
          the 'directories' configuration tag is empty.
        - Verify that the 'wazuh-syscheckd' daemon does not generate a debug log when
          the 'directories' configuration tag is not empty.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it
                       is combined with the testing directories to be monitored defined in this module.

    expected_output:
        - r'Empty directories tag found in the configuration.'

    tags:
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Check that the warning is displayed when there is no directory.
    for section in get_configuration['sections']:
        if section['section'] == 'syscheck':
            if not section['elements'][1]['directories']['value']:
                wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_empty_directories,
                                        error_message='Did not receive expected '
                                                      '"DEBUG: (6338): Empty directories tag found in the configuration" '
                                                      'event').result()
            # Check that the message is not displayed when the directory is specified.
            else:
                with pytest.raises(TimeoutError):
                    event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                    callback=callback_empty_directories).result()
                    raise AttributeError(f'Unexpected event {event}')
