# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (CHECK_ALL, LOG_FILE_PATH,
                               regular_file_cud)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories
options = {CHECK_ALL}

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': ''},
                                                   {'FIM_MODE': {'realtime': 'yes'}},
                                                   {'FIM_MODE': {'whodata': 'yes'}}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled'},
                                                     {'fim_mode': 'realtime'},
                                                     {'fim_mode': 'whodata'}]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests
