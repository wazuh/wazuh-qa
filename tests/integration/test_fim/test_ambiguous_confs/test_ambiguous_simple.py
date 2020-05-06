# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, regular_file_cud, WAZUH_PATH,
                               CHECK_ALL, CHECK_GROUP, CHECK_INODE,
                               CHECK_MTIME, CHECK_OWNER,
                               CHECK_PERM, CHECK_SHA256SUM,
                               CHECK_SIZE, CHECK_SUM, REQUIRED_ATTRIBUTES, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(
    test_data_path, 'wazuh_conf_simple_win32.yaml' if sys.platform == 'win32' else 'wazuh_conf_simple.yaml')
checkdir_default = os.path.join(PREFIX, 'checkdir_default')
checkdir_checkall = os.path.join(checkdir_default, 'checkdir_checkall')
checkdir_no_inode = os.path.join(checkdir_checkall, 'checkdir_no_inode')
checkdir_no_checksum = os.path.join(checkdir_no_inode, 'checkdir_no_checksum')
test_directories = [os.path.join(PREFIX, 'testdir'), os.path.join(PREFIX, 'testdir', 'subdir'),
                    os.path.join(PREFIX, 'recursiondir'), os.path.join(PREFIX, 'recursiondir_tag'),
                    os.path.join(PREFIX, 'recursiondir_no_tag'), checkdir_default, checkdir_checkall,
                    checkdir_no_inode, checkdir_no_checksum]
testdir, subdir = test_directories[0:2]
testdir_recursion = test_directories[2]
testdir_recursion_tag = test_directories[3]
testdir_recursion_no_tag = test_directories[4]

check_list = {CHECK_SIZE} | {CHECK_PERM} | {CHECK_OWNER} | {CHECK_GROUP} | {CHECK_SHA256SUM} | {CHECK_MTIME}
if sys.platform != 'win32':
    check_list = check_list | {CHECK_INODE}
parametrize_list = [(checkdir_default, check_list),
                    (checkdir_checkall, REQUIRED_ATTRIBUTES[CHECK_ALL]),
                    (checkdir_no_inode, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_INODE}),
                    (checkdir_no_checksum, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM])
                    ]

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

def tag_validator(event):
    """Validate tags event property exists in the event."""
    assert tag == event['data']['tags'], 'defined_tags are not equal'


def no_tag_validator(event):
    """Validate tags event property does not exist in the event."""
    assert 'tags' not in event['data'].keys(), "'tags' key found in event"


def _test_recursion_cud(ini, fin, path, recursion_subdir, scheduled,
                        min_timeout, triggers_event, validators_after_cud=None):
    """Apply `regular_file_cud` on different recursion levels.

    Iterate from `ini` recursion level to `fin` recursion level, creating the
    corresponding subdirectory and applying the `regular_file_cud` function on it.

    Parameters
    ----------
    ini : int
        Initial level of recursion.
    fin : int
        Final level of recursion.
    path : string
        Path over which subdirectories will be created.
    recursion_subdir : string
        Name for subdirectories.
    scheduled : bool
        Determine if there will be time travels or not
    min_timeout : int
        Minimum timeout
    triggers_event : bool
        determine if the event should be raised or not.
    validators_after_cud : list, optional
        functions that validate an event triggered when a new file is created, modified
    or deleted. Each function must accept a param to receive the event to be validated.

    Returns
    -------
    path : string
        Full path after adding all the subdirectories.
    """
    for n in range(ini, fin):
        path = os.path.join(path, recursion_subdir + str(n + 1))
        regular_file_cud(path, wazuh_log_monitor, time_travel=scheduled, min_timeout=min_timeout,
                         triggers_event=triggers_event, validators_after_cud=validators_after_cud)
    return path


# tests
@pytest.mark.parametrize('folders, tags_to_apply', [
    ([testdir, subdir], {'ambiguous_restrict'})
])
def test_ambiguous_restrict(folders, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                            wait_for_initial_scan):
    """Check restrict configuration events.

    Check if syscheck detects regular file changes (add, modify, delete) depending on its restrict configuration.

    /testdir -> has a restrict configuration
    /testdir/subdir -> has no restrict configuration
    Only /testdir/subdir events should appear in ossec.log

    This test is intended to be used with valid configurations files. Each execution of this test will configure
    the environment properly, restart the service and wait for the initial scan.

    Parameters
    ----------
    folders : list
        Monitored directories
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    file_list = ['example.csv']
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    regular_file_cud(folders[0], wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=False)

    regular_file_cud(folders[1], wazuh_log_monitor, file_list=file_list,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=True)


@pytest.mark.parametrize('folders, tags_to_apply', [
    ([testdir, subdir], {'ambiguous_report_changes'})
])
def test_ambiguous_report(folders, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                          wait_for_initial_scan):
    """Check content_changes field for each event

    Check if syscheck detects or not the content_changes field for each event depending on its report_changes
    attribute.

    This test validates both situations, making sure that if report_changes='no', there won't be a
    content_changes event property.

    Parameters
    ----------
    folders : list
        Monitored directories
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    def report_changes_validator(event):
        """Validate content_changes event property exists in the event."""
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
            striped = folder.strip(os.sep) if sys.platform == 'darwin' else folder.strip(PREFIX)
            diff_file = os.path.join(diff_file, striped, file)

            assert os.path.exists(diff_file), f'{diff_file} does not exist'
            assert event['data'].get('content_changes') is not None, f'content_changes is empty'

    def no_report_changes_validator(event):
        """Validate content_changes event property does not exist in the event."""
        for file in file_list:
            diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')
            if sys.platform == 'win32':
                diff_file = os.path.join(diff_file, 'c')
            striped = folder.strip(os.sep) if sys.platform == 'darwin' else folder.strip(PREFIX)
            diff_file = os.path.join(diff_file, striped, file)

            assert not os.path.exists(diff_file), f'{diff_file} exists'
            assert 'content_changes' not in event['data'].keys(), f"'content_changes' in event"

    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    file_list = ['regular']
    folder = folders[1]

    # Check if create, update and delete events in folders[1] contain the field 'content_changes'.
    regular_file_cud(folders[1], wazuh_log_monitor, file_list=file_list, time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[report_changes_validator])

    # Check if events in folders[0] do not contain the field 'content_changes'
    folder = folders[0]
    regular_file_cud(folders[0], wazuh_log_monitor, file_list=file_list, time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, triggers_event=True,
                     validators_after_update=[no_report_changes_validator])


@pytest.mark.parametrize('folders, tags_to_apply', [
    ([testdir, subdir], {'ambiguous_tags'})
])
def test_ambiguous_tags(folders, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                        wait_for_initial_scan):
    """Check if syscheck detects the event property 'tags' for each event.

    This test validates both situations, making sure that if tags='no', there won't be a
    tags event property.

    Parameters
    ----------
    folders : list
        Monitored directories
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    # Check that events inside folder[0] do not contain the key 'tags'.
    regular_file_cud(folders[0], wazuh_log_monitor,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[no_tag_validator])

    # Check that events inside folder[1] do contain the key 'tags'.
    regular_file_cud(folders[1], wazuh_log_monitor,
                     time_travel=scheduled,
                     min_timeout=global_parameters.default_timeout, validators_after_cud=[tag_validator])


@pytest.mark.parametrize('dirname, recursion_level, tags_to_apply', [
    (testdir_recursion, 1, {'ambiguous_recursion_over'}),
    (testdir_recursion, 4, {'ambiguous_recursion'})
])
def test_ambiguous_recursion(dirname, recursion_level, tags_to_apply, get_configuration, configure_environment,
                             restart_syscheckd, wait_for_initial_scan):
    """Check alerts for each level defined in recursion_level

    Check if syscheck detects alerts for each level defined in the recursion_level attribute.
    This overwrites the default value, restricting it.

    If we set recursion_level=1 and we have this monitored directory /testdir
    It will only monitor /testdir and /testdir/subdir
    If we had /testdir/subdir/subdir2, /subdir2 wouldn't be monitored

    Parameters
    ----------
    dirname : string
        Name of the monitored directory
    recursion_level : int
        Value of the recursion_level attribute
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    recursion_subdir = 'subdir'
    path = dirname

    # Iterate from ini to fin and verify that events are generated in the nested directories.
    path = _test_recursion_cud(ini=0, fin=recursion_level, path=path,
                               recursion_subdir=recursion_subdir,
                               scheduled=scheduled,
                               min_timeout=global_parameters.default_timeout, triggers_event=True)

    # Iterate from ini to fin and verify that events are NOT generated in nested directories
    # beyond the established recursion level.
    _test_recursion_cud(ini=recursion_level, fin=4, path=path,
                        recursion_subdir=recursion_subdir,
                        scheduled=scheduled,
                        min_timeout=global_parameters.default_timeout, triggers_event=False)


@pytest.mark.parametrize('dirnames, recursion_level, triggers_event, tags_to_apply', [
    ([testdir_recursion_tag, testdir_recursion_no_tag], 2, True, {'ambiguous_recursion_tag'}),
    ([testdir_recursion_tag, testdir_recursion_no_tag], 2, False, {'ambiguous_no_recursion_tag'})
])
def test_ambiguous_recursion_tag(dirnames, recursion_level, triggers_event, tags_to_apply, get_configuration,
                                 configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check alerts for each level defined in recursion_level with tags

    Check if syscheck detects alerts for each level defined in the recursion_level attribute and
    if it detects the event property 'tags' for each of them.
    This overwrites the default value, restricting it.

    Parameters
    ----------
    dirnames : list
        Monitored directories
    recursion_level : int
        Value of the recursion_level attribute
    triggers_event : bool
        determine if the event should be raised or not.
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    recursion_subdir = 'subdir'

    # Iterate from ini to fin and verify that events generated in the nested directories contain the key 'tags'.
    _test_recursion_cud(ini=0, fin=recursion_level, path=dirnames[0],
                        recursion_subdir=recursion_subdir,
                        scheduled=scheduled, min_timeout=global_parameters.default_timeout,
                        triggers_event=triggers_event, validators_after_cud=[tag_validator])

    # Iterate from ini to fin and verify that events generated in the nested directories DO NOT contain the key 'tags'.
    _test_recursion_cud(ini=0, fin=recursion_level, path=dirnames[1],
                        recursion_subdir=recursion_subdir,
                        scheduled=scheduled, min_timeout=global_parameters.default_timeout,
                        triggers_event=triggers_event, validators_after_cud=[no_tag_validator])


@pytest.mark.parametrize('tags_to_apply', [
    {'ambiguous_check'}
])
@pytest.mark.parametrize('dirname, checkers', parametrize_list)
def test_ambiguous_check(dirname, checkers, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                         wait_for_initial_scan):
    """Check if syscheck detects every check set in the configuration.

    Check are read from left to right, overwriting any ambiguous configuration.

    If we set check_all='yes' and then check_inode='no' for the same directory, syscheck must send an event
    containing every possible check without inode.

    Parameters
    ----------
    dirname : string
        Name of the monitored directory
    checkers : set
        Checks to be compared to the actual event check list (the one we get from the event)
    tags_to_apply : set
        Run test if matches with a configuration identifier, skip otherwise
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'

    regular_file_cud(dirname, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, options=checkers,
                     time_travel=scheduled)
