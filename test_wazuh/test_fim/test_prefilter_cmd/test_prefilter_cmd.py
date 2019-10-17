# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, detect_initial_scan
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, restart_wazuh_daemon, truncate_file)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')
                    ]
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': '', 'PREFILTER_CMD': '/usr/sbin/prelink -y'},
                                                   {'FIM_MODE': {'realtime': 'yes'},
                                                    'PREFILTER_CMD': '/usr/sbin/prelink -y'},
                                                   {'FIM_MODE': {'whodata': 'yes'},
                                                    'PREFILTER_CMD': '/usr/sbin/prelink -y'}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled', 'prefilter_cmd': '/usr/sbin/prelink -y'},
                                                     {'fim_mode': 'realtime', 'prefilter_cmd': '/usr/sbin/prelink -y'},
                                                     {'fim_mode': 'whodata', 'prefilter_cmd': '/usr/sbin/prelink -y'}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'prefilter_cmd'})
])
def test_prefilter_cmd(tags_to_apply, get_configuration, configure_environment):
    """Checks if prelink is installed and syscheck works."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if get_configuration['metadata']['prefilter_cmd'] == '/usr/sbin/prelink -y':
        prelink = get_configuration['metadata']['prefilter_cmd'].split(' ')[0]
        assert os.path.exists(prelink), f'Prelink is not installed'
        truncate_file(LOG_FILE_PATH)
        restart_wazuh_daemon('ossec-syscheckd')
        detect_initial_scan(wazuh_log_monitor)
