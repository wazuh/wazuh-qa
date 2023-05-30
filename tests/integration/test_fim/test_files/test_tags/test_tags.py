'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM events include
       all tags set in the 'tags' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_tags

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
    - fim_tags
'''
import os

import pytest
from wazuh_testing import T_30, LOG_FILE_PATH
from wazuh_testing.modules.fim.utils import  regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# Variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir_tags'),
                    os.path.join(PREFIX, 'testdir_tags', 'subdir'),
                    os.path.join(PREFIX, 'test dir'),
                    os.path.join(PREFIX, 'test dir', 'subdir')
                    ]

directory_str = ','.join([test_directories[0], test_directories[2]])


# configurations
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
tags = ['tag1', 'tág', '0tag', '000', 'a' * 1000]
# Create an increasing tag set. I.e.: ['tag1', 'tag1,tag2', 'tag1,tag2,tag3']
test_tags = [tags[0], ','.join(tags)]

p, m = generate_params(extra_params={'TEST_DIRECTORIES': directory_str},
                       apply_to_all=({'FIM_TAGS': tag} for tag in tags))

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=p,
                                           metadata=m
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('folder', test_directories)
@pytest.mark.parametrize('name, content', [
    ('file1', 'Sample content'),
    ('file2', b'Sample content')
])
@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_tags(folder, name, content,
              get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates the tags required for each event
                 depending on the values set in the 'tags' attribute. This attribute allows adding
                 tags to alerts for monitored directories. For this purpose, the test will monitor a
                 folder and make file operations inside it. Finally, it will verify that FIM events
                 generated include in the 'tags' field all tags set in the configuration.

    wazuh_min_version: 4.2.0

    tier: 1

    parameters:
        - folder:
            type: str
            brief: Monitored directory.
        - name:
            type: str
            brief: Name of the testing file to be created.
        - content:
            type: str
            brief: Content to fill the testing file.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the `ossec.log` file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events include all tags set in the 'tags' attribute.

    input_description: A test case is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and,
                       it is combined with the testing directory to be monitored defined
                       in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    defined_tags = get_configuration['metadata']['fim_tags']
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    
    def tag_validator(event):
        assert defined_tags == event['data']['tags'], f'defined_tags are not equal'

    files = {name: content}

    regular_file_cud(folder, wazuh_log_monitor, file_list=files, min_timeout=T_30,
                     validators_after_cud=[tag_validator])
