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
                                 load_wazuh_configurations, get_wazuh_conf, set_section_wazuh_conf, write_wazuh_conf,
                                 restart_wazuh_service)

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


# @pytest.fixture(scope='module', params=configurations)
# def configure_environment(get_configuration, request):
#     """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""
#     print(f"Setting a custom environment: {str(get_configuration)}")
#
#     # save current configuration
#     backup_config = get_wazuh_conf()
#     # configuration for testing
#     test_config = set_section_wazuh_conf(get_configuration.get('section'),
#                                          get_configuration.get('elements'))
#
#     # create test directories
#     test_directories = getattr(request.module, 'test_directories')
#     for test_dir in test_directories:
#         os.makedirs(test_dir, exist_ok=True)
#
#     # create nfs mount point
#     subprocess.call(['./data/create_nfs.sh'])
#
#     # set new configuration
#     write_wazuh_conf(test_config)
#
#     yield
#
#     # remove created folders (parents)
#     for test_dir in test_directories:
#         shutil.rmtree(test_dir, ignore_errors=True)
#
#     # remove nfs created folder
#     subprocess.call(['./data/remove_nfs.sh'])
#
#     # restore previous configuration
#     write_wazuh_conf(backup_config)
#
#     if hasattr(request.module, 'force_restart_after_restoring'):
#         if getattr(request.module, 'force_restart_after_restoring'):
#             restart_wazuh_service()


@pytest.fixture(scope='session')
def configure_nfs():
    # create nfs mount point
    subprocess.call(['./data/configure_nfs.sh'])
    subprocess.call(['./data/create_nfs.sh'])
    yield
    # remove nfs created folder
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
    """ Check if syscheck is skipping the directory based on its skip configuration """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    timeout = 3
    if tags_to_apply == {'skip_proc'}:
        timeout = 100

    if get_configuration['metadata']['skip'] == 'yes':
        trigger = False
    else:
        trigger = True

    if tags_to_apply == {'skip_proc'} or {'skip_sys'}:
        if trigger:
            event = wazuh_log_monitor.start(timeout=8, callback=callback_detect_integrity_event).result()
            assert '/proc' or '/sys' in event['data'].get('path'), f'Path not found in event'
        else:
            with pytest.raises(TimeoutError):
                wazuh_log_monitor.start(timeout=5, callback=callback_detect_integrity_event)

    else:
        regular_file_cud(directory, wazuh_log_monitor,
                         time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                         min_timeout=timeout, triggers_event=trigger)
