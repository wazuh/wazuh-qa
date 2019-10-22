# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_integrity_event,
                               regular_file_cud)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]

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


@pytest.fixture(scope='session')
def configure_nfs():
    # create and configure nfs mount point
    subprocess.call(['./data/configure_nfs.sh'])
    yield
    # remove nfs
    subprocess.call(['./data/remove_nfs.sh'])
    shutil.rmtree(os.path.join('/', 'media', 'nfs-folder'), ignore_errors=True)


# tests


@pytest.mark.parametrize('directory,  tags_to_apply', [
    (os.path.join('/', 'proc'), {'skip_proc'}),
    (os.path.join('/', 'sys'), {'skip_sys'}),
    (os.path.join('/', 'dev'), {'skip_dev'}),
    (os.path.join('/', 'nfs-mount-point'), {'skip_nfs'})
])
def test_skip(directory, tags_to_apply,
              get_configuration, configure_environment, configure_nfs,
              restart_syscheckd, wait_for_initial_scan):
    """ Check if syscheck is skipping the directory based on its skip configuration

    :param directory: Directory that will be monitored
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    timeout = 3
    if tags_to_apply == {'skip_proc'}:
        timeout = 100

    if get_configuration['metadata']['skip'] == 'yes':
        trigger = False
    else:
        trigger = True

    if tags_to_apply == {'skip_proc'} or tags_to_apply == {'skip_sys'}:
        if trigger:
            event = wazuh_log_monitor.start(timeout=8, callback=callback_detect_integrity_event).result()
            assert any(path in event['data'].get('path') for path in ['/proc', '/sys'])
        else:
            with pytest.raises(TimeoutError):
                wazuh_log_monitor.start(timeout=5, callback=callback_detect_integrity_event)

    else:
        regular_file_cud(directory, wazuh_log_monitor,
                         time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                         min_timeout=timeout, triggers_event=trigger)
