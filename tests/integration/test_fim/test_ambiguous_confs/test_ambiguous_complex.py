# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import timedelta

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, regular_file_cud, create_file, WAZUH_PATH,
                               callback_restricted, REGULAR, generate_params)
from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(
    test_data_path, 'wazuh_conf_complex_win32.yaml' if sys.platform == 'win32' else 'wazuh_conf_complex.yaml')
testdir = os.path.join(PREFIX, 'testdir')
subdir = 'subdir'
test_directories = [testdir]
for n in range(5):
    testdir = (os.path.join(testdir, subdir + str(n + 1)))
    test_directories.append(testdir)

tag = 'Sample_tag'

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

conf_params, conf_metadata = generate_params(extra_params={'TAGS': tag})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# functions

def apply_test(directory: str, attributes: list, trigger: bool, check_list: list, args: tuple):
    """ Applies each specified test for every given directory. If it doesn't detect any attribute,
        it will check the default configuration.

    :param directory: Directory to test
    :param attributes: List with each attribute given in conf. Used to call each test
    :param trigger: Boolean to expect events or not
    :param check_list: List with all the checks detected in conf
    :param args: Tuple with additional parameters passed to each test
    :return:
    """
    for attribute in attributes:
        getattr(sys.modules[__name__], f'check_{attribute}')(directory, trigger, check_list, *args)


def get_dir_and_attributes(configuration):
    """ Returns a tuple with all the conf detected and a list of checker lists.
        configuration must be: get_configuration['elements']

        The tuple has the following structure:
        Tuple -> (config_list, directory_check_list)
            - config_list -> [{dir_1: [attr_list_1]}, ... , {dir_n: attr_list_n}]
            - directory_check_list -> [[checkers_dir_1], ... , [checkers_dir_n]]

    :param configuration: get_configuration['elements']
    :return: Tuple with two values. Both a list
    """
    config_list = []
    directory_check_list = []
    for configs in configuration:
        for conf in configs:
            # For every 'directories' field, detect and save its value and attributes
            if conf == 'directories':
                attributes = []
                check_list = []
                default = True
                for attribute in configs['directories']['attributes']:
                    # If the attribute is not a string (fim_mode: '')
                    if not isinstance(attribute, str):
                        field = list(attribute.keys())[0]
                        # If the attribute is "check_*: 'yes'", save it in the check list
                        if 'check_' in field:
                            if list(attribute.values())[0] == 'yes':
                                check_list.append(field)
                        # If the attribute is different from the monitoring ones, save it and set it is not
                        # a default conf. It only works with realtime for now
                        elif field != 'realtime' and field != 'whodata':
                            attributes.append(field)
                            default = False
                # If no valuable attributes were detected, assume it is a default conf
                if default:
                    attributes.append('default')
                config_list.append({configs['directories'].get('value'): attributes})
                directory_check_list.append(check_list)

    return config_list, directory_check_list


def check_report_changes(directory, trigger, check_list, file_list, timeout, scheduled):
    """ Standard report_changes test """

    def report_changes_validator(event):
        """ Validate content_changes attribute exists in the event """
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
                diff_file = os.path.join(diff_file, directory.strip('C:\\'), file)
            else:
                diff_file = os.path.join(diff_file, directory.strip('/'), file)
            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    regular_file_cud(directory, wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled,
                     min_timeout=timeout, triggers_event=trigger, options=get_checkers(check_list),
                     validators_after_update=[report_changes_validator])


def check_default(directory, trigger, check_list, file_list, timeout, scheduled):
    """ Standard default conf test """
    regular_file_cud(directory, wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled, options=get_checkers(check_list),
                     min_timeout=timeout, triggers_event=trigger)


def check_restrict(directory, trigger, check_list, file_list, timeout, scheduled):
    """ Standard restrict attribute test """

    create_file(REGULAR, directory, file_list[0], content='')
    if scheduled:
        TimeMachine.travel_to_future(timedelta(hours=13))
    while True:
        ignored_file = wazuh_log_monitor.start(timeout=timeout,
                                               callback=callback_restricted).result()
        if ignored_file == os.path.join(directory, file_list[0]):
            break


def check_tags(directory, trigger, check_list, file_list, timeout, scheduled):
    """ Standard tags attribute test """

    def tag_validator(event):
        """ Validate tag attribute exists in the event """
        assert tag == event['data']['tags'], f'defined_tags are not equal'

    regular_file_cud(directory, wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled, options=get_checkers(check_list),
                     min_timeout=timeout, triggers_event=trigger, validators_after_cud=[tag_validator])


def get_checkers(check_list):
    """ Transform check_list to set. It is scalable in case we want to make set operations for
        more complex conf

    :param check_list: List with every check detected in conf
    :return:
    """
    checkers = set()
    if check_list:
        for check in check_list:
            checkers.add(check)
        return checkers
    return None


# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'complex'})
])
def test_ambiguous_complex(tags_to_apply,
                           get_configuration, configure_environment,
                           restart_syscheckd, wait_for_initial_scan):
    """ Automatic test for each configuration given in the yaml.

    The main purpose of this test is to check that syscheck will apply different configurations between subdirectories
    properly. Example:

    <directories realtime='yes' report_changes='yes' check_all='yes' check_owner='no'> /testdir </directories>
    <directories realtime='yes' report_changes='no' check_sum='no' check_owner='yes'> /testdir/subdir </directories>

    * This test is intended to be used with valid configurations files. Each execution of this test will configure
      the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Standard params for each test
    file_list = ['example.csv']
    min_timeout = global_parameters.default_timeout
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    conf_list, check_list = get_dir_and_attributes(get_configuration['elements'])
    param = (file_list, min_timeout, scheduled)
    # For every directory, apply each test depending of its attributes.
    # We assume we've set restrict attribute so it should not expect events
    # For further functionality with restrict, run ../test_restrict tests
    for directory, checkers in zip(conf_list, check_list):
        for path, attributes in directory.items():
            trigger = False if 'restrict' in attributes else True
            apply_test(path, attributes, trigger, checkers, param)
