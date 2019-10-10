# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import itertools
import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud
from wazuh_testing.tools import FileMonitor, load_wazuh_configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join('/', 'testdir_tags'),
                    os.path.join('/', 'testdir_tags', 'subdir'),
                    os.path.join('/', 'test dir'),
                    os.path.join('/', 'test dir', 'subdir')
                    ]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
tags = ['tag1', 'tág', '0tag', '000', 'a' * 1000]
# Create an incresing tag set. I.e.: ['tag1', 'tag1,tag2', 'tag1,tag2,tag3']
test_tags = [tags[0], ','.join(tags)]
fim_modes = ['', {'realtime': 'yes'}, {'whodata': 'yes'}]
fim_modes_metadata = ['scheduled', 'realtime', 'whodata']
params = [{'FIM_MODE': fim_mode,
           'FIM_TAGS': test_tag}
          for fim_mode, test_tag in itertools.product(fim_modes, test_tags)]
metadata = [{'fim_mode': fim_mode,
             'fim_tags': test_tag}
            for fim_mode, test_tag in itertools.product(fim_modes_metadata, test_tags)]
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params,
                                           metadata=metadata
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
              get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):

    defined_tags = get_configuration['metadata']['fim_tags']

    def tag_validator(event):
        assert(defined_tags == event['data']['tags'])

    files = {name: content}

    regular_file_cud(folder, wazuh_log_monitor, file_list=files,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=3, validators_after_cud=[tag_validator]
                     )
