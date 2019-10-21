# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH,
                               callback_detect_integrity_event, regular_file_cud)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
testdir1 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': '', 'SKIP': 'yes'},
                                                   {'FIM_MODE': '', 'SKIP': 'no'},
                                                   {'FIM_MODE': {'realtime': 'yes'}, 'SKIP': 'yes'},
                                                   {'FIM_MODE': {'realtime': 'yes'}, 'SKIP': 'no'},
                                                   {'FIM_MODE': {'whodata': 'yes'}, 'SKIP': 'yes'},
                                                   {'FIM_MODE': {'whodata': 'yes'}, 'SKIP': 'no'}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled', 'skip': 'yes'},
                                                     {'fim_mode': 'scheduled', 'skip': 'no'},
                                                     {'fim_mode': 'realtime', 'skip': 'yes'},
                                                     {'fim_mode': 'realtime', 'skip': 'no'},
                                                     {'fim_mode': 'whodata', 'skip': 'yes'},
                                                     {'fim_mode': 'whodata', 'skip': 'no'}
                                                     ]
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('directory,  tags_to_apply', [
    # (os.path.join('/', 'nfs'), {'skip_nfs'}),
    (os.path.join('/', 'dev'), {'skip_dev'})
    # (os.path.join('/', 'proc'), {'skip_proc'}),
    # (os.path.join('/', 'sys'), {'skip_sys'})
])
def test_regular_file_changes(directory, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_initial_scan):
    """ Checks if syscheckd detects regular file changes (add, modify, delete)

    :param folder: Directory where the files will be created
    :param checkers: Dict of syscheck checkers (check_all)
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if get_configuration['metadata']['skip'] == 'yes':
        trigger = False
    else:
        trigger = True
    regular_file_cud(directory, wazuh_log_monitor,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=3, triggers_event=trigger)
