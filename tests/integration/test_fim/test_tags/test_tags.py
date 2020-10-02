# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params
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
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

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
def test_tags(folder, name, content,
              get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check the tags functionality by applying some tags an ensuring the events raised for the monitored directory has
    the expected tags.

    Parameters
    ----------
    folder : str
        Directory where the file is being created.
    name : str
        Name of the file to be created.
    content : str, bytes
        Content to fill the new file.
    """
    defined_tags = get_configuration['metadata']['fim_tags']

    def tag_validator(event):
        assert defined_tags == event['data']['tags'], f'defined_tags are not equal'

    files = {name: content}

    regular_file_cud(folder, wazuh_log_monitor, file_list=files,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[tag_validator]
                     )
