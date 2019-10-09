# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import pytest
import re

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event, regular_file_cud
from wazuh_testing.tools import FileMonitor, check_apply_test, load_wazuh_configurations


# Variables

dir_no_recursion = "/test_no_recursion"
dir_recursion_1 = "/test_recursion_1"
dir_recursion_5 = "/test_recursion_5"
dir_recursion_320 = "/test_recursion_320"
subdir = "subdir"

dir_no_recursion_space = "/test no recursion"
dir_recursion_1_space = "/test recursion 1"
dir_recursion_5_space = "/test recursion 5"
dir_recursion_320_space = "/test recursion 320"
subdir_space = "sub dir "

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [
    dir_no_recursion,
    dir_recursion_1,
    dir_recursion_5,
    dir_recursion_320,
    dir_no_recursion_space,
    dir_recursion_1_space,
    dir_recursion_5_space,
    dir_recursion_320_space
]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# Configurations

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=[{'FIM_MODE': ''},
                                                   {'FIM_MODE': {'realtime': 'yes'}},
                                                   {'FIM_MODE': {'whodata': 'yes'}}
                                                   ],
                                           metadata=[{'fim_mode': 'scheduled'},
                                                     {'fim_mode': 'realtime'},
                                                     {'fim_mode': 'whodata'}
                                                     ]
                                           )


# Functions

def check_config_applies(applies_to_config, get_configuration):
    """Checks if the processed conf file matches with the one specified by parameter.
    If not, the test is skipped.

    :param applies_to_config string The .conf file name to apply.
    """
    if not re.search(applies_to_config, get_configuration):
        pytest.skip("Does not apply to this config file")


def recursion_test(dirname, subdirname, recursion_level, num_files=1,
                   timeout=1, threshold_true=2, threshold_false=2, is_scheduled=False):
    """Checks recursion_level functionality over the first and last n-directories of the dirname hierarchy 
    by creating, modifying and deleting some files in them. It will create all directories and 
    subdirectories needed using the info provided by parameter.

    :param dirname string The path being monitored by syscheck (indicated in the .conf file)
    :param subdirname string The name of the subdirectories that will be created during the execution for testing purpouses.
    :param recursion_level int Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    :param num_files The number of regular files that the test will use for each directory
    :param timeout int Max time to wait until an event is raised.
    :param threshold_true Number of directories where the test will monitor events 
    :param threshold_false Number of directories exceding the specified recursion_level to verify events are not raised
    :para is_scheduled bool If True the internal date will be modified to trigger scheduled checks by syschecks. False if realtime or Whodata.
    """
    path = dirname

    # Check True (Within the specified recursion level)
    for n in range(recursion_level):
        path = os.path.join(path, subdirname + str(n+1))
        if ((recursion_level < threshold_true * 2) or
            (recursion_level >= threshold_true * 2 and n < threshold_true) or
            (recursion_level >= threshold_true * 2 and n > recursion_level - threshold_true)):
            regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled,
                             n_regular=num_files, min_timeout=timeout)

    # Check False (exceding the specified recursion_level)
    for n in range(recursion_level, recursion_level + threshold_false):
        path = os.path.join(path, subdirname + str(n+1))
        regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled,
                         n_regular=num_files, min_timeout=timeout, triggers_event=False)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    return request.param


# Tests

@pytest.mark.parametrize('dirname, subdirname, recursion_level', [
    (dir_no_recursion, subdir, 0),
    (dir_no_recursion_space, subdir_space, 0),
    (dir_recursion_1, subdir, 1),
    (dir_recursion_1_space, subdir_space, 1),
    (dir_recursion_5, subdir, 5),
    (dir_recursion_5_space, subdir_space, 5),
    (dir_recursion_320, subdir, 318),
    (dir_recursion_320_space, subdir_space, 318)
])
def test_recursion_level(dirname, subdirname, recursion_level,
                         get_configuration, configure_environment,
                         restart_syscheckd, wait_for_initial_scan):
    """Checks if files are correctly detected by syscheck with recursion level using scheduled, realtime and whodata monitoring

    This test is intended to be used with valid ignore configurations. It applies RegEx to match the name 
    of the configuration file where the test applies. If the configuration file does not match the test 
    is skipped.

    :param dirname string The path being monitored by syscheck (indicated in the .conf file)
    :param subdirname string The name of the subdirectories that will be created during the execution for testing purpouses.
    :param recursion_level int Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    """
    if get_configuration['metadata']['fim_mode'] == 'scheduled':
        recursion_test(dirname, subdirname, recursion_level, is_scheduled=True, timeout=3)
    else:
        recursion_test(dirname, subdirname, recursion_level, timeout=3)
