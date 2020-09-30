# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess
import uuid
from datetime import timedelta
from unittest.mock import patch

import distro
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, regular_file_cud, detect_initial_scan, callback_detect_event,
                               generate_params, callback_detect_integrity_state, check_time_travel, delete_file)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import set_section_wazuh_conf, load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import restart_wazuh_with_new_conf
from wazuh_testing.tools.time import TimeMachine

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir = os.path.join(PREFIX, 'testdir1')
test_directories = [testdir]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

def change_conf(dir_value):
    p, m = generate_params(extra_params={'DIRECTORY': dir_value},
                           apply_to_all=({'SKIP': skip} for skip in ['yes', 'no']),
                           modes=['scheduled'])

    return load_wazuh_configurations(configurations_path, __name__,
                                     params=p,
                                     metadata=m
                                     )


configurations = change_conf(testdir)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope='session')
def configure_nfs():
    """Call NFS scripts to create and configure a NFS mount point"""
    if not os.path.exists('/nfs-mount-point'):
        path = os.path.dirname(os.path.abspath(__file__))
        rpms = ['centos', 'fedora', 'rhel']
        debs = ['ubuntu', 'debian', 'linuxmint']
        if distro.id() in rpms:
            conf_script = 'configure_nfs_rpm.sh'
            remove_script = 'remove_nfs_rpm.sh'
        elif distro.id() in debs:
            conf_script = 'configure_nfs_deb.sh'
            remove_script = 'remove_nfs_deb.sh'
        else:
            pytest.fail('The OS is not supported for this test')
        subprocess.call([f'{path}/data/{conf_script}'])
        yield

        # remove nfs
        subprocess.call([f'{path}/data/{remove_script}'])
        shutil.rmtree(os.path.join('/', 'media', 'nfs-folder'), ignore_errors=True)
    else:
        yield


def extra_configuration_before_yield():
    # Load isofs module in kernel just in case
    subprocess.call(['modprobe', 'isofs'])


# tests

def test_skip_proc(get_configuration, configure_environment, restart_syscheckd, wait_for_syscheck_start):
    """Check if syscheckd skips /proc when setting 'skip_proc="yes"'."""
    check_apply_test({'skip_proc'}, get_configuration['tags'])
    trigger = get_configuration['metadata']['skip'] == 'no'

    if trigger:
        proc = subprocess.Popen(["python3", f"{os.path.dirname(os.path.abspath(__file__))}/data/proc.py"])

        # Change configuration, monitoring the PID path in /proc
        # Monitor only /proc/PID to expect only these events. Otherwise, it will fail due to Timeouts since
        # integrity scans will take too long
        new_conf = change_conf(f'/proc/{proc.pid}')
        new_ossec_conf = []

        # Get new skip_proc configuration
        for conf in new_conf:
            if conf['metadata']['skip'] == 'no' and conf['tags'] == ['skip_proc']:
                new_ossec_conf = set_section_wazuh_conf(conf.get('sections'))
        restart_wazuh_with_new_conf(new_ossec_conf)
        truncate_file(LOG_FILE_PATH)
        proc_monitor = FileMonitor(LOG_FILE_PATH)
        detect_initial_scan(proc_monitor)

        # Do not expect any 'Sending event'
        with pytest.raises(TimeoutError):
            proc_monitor.start(timeout=3, callback=callback_detect_event,
                               error_message='Did not receive expected "Sending FIM event: ..." event')

        check_time_travel(time_travel=True, monitor=wazuh_log_monitor)

        found_event = False
        while not found_event:
            event = proc_monitor.start(timeout=5, callback=callback_detect_event,
                                       error_message='Did not receive expected '
                                                     '"Sending FIM event: ..." event').result()
            if f'/proc/{proc.pid}/' in event['data'].get('path'):
                found_event = True

        # Kill the process
        subprocess.Popen(["kill", "-9", str(proc.pid)])

    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_integrity_state)
            raise AttributeError(f'Unexpected event {event}')


def test_skip_sys(get_configuration, configure_environment, restart_syscheckd, wait_for_syscheck_start):
    """Check if syscheckd skips /sys when setting 'skip_sys="yes"'."""
    check_apply_test({'skip_sys'}, get_configuration['tags'])
    trigger = get_configuration['metadata']['skip'] == 'no'

    if trigger:
        # If /sys/module/isofs does not exist, use 'modprobe isofs'
        assert os.path.exists('/sys/module/isofs'), f'/sys/module/isofs does not exist'

        # Do not expect any 'Sending event'
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
            raise AttributeError(f'Unexpected event {event}')

        # Remove module isofs and travel to future to check alerts
        subprocess.Popen(["modprobe", "-r", "isofs"])
        TimeMachine.travel_to_future(timedelta(hours=13))

        # Detect at least one 'delete' event in /sys/module/isofs path
        event = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event,
                                        error_message='Did not receive expected '
                                                      '"Sending FIM event: ..." event').result()
        assert event['data'].get('type') == 'deleted' and '/sys/module/isofs' in event['data'].get('path'), \
            f'Sys event not detected'

        # Restore module isofs
        subprocess.Popen(["modprobe", "isofs"])
    else:
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_integrity_state)
            raise AttributeError(f'Unexpected event {event}')


@pytest.mark.parametrize('directory, tags_to_apply', [
    (os.path.join('/', 'dev'), {'skip_dev'})
])
@patch('wazuh_testing.fim.modify_file_inode')
def test_skip_dev(modify_inode_mock, directory, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                  wait_for_syscheck_start):
    """Check if syscheckd skips /dev when setting 'skip_dev="yes"'.

    /proc, /sys, /dev and nfs directories are special directories. Unless it is specified with skip_*='no', syscheck
    will skip these directories. If not, they will be monitored like a normal directory.

    Parameters
    ----------
    directory : str
        Directory that will be monitored.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    trigger = get_configuration['metadata']['skip'] == 'no'

    regular_file_cud(directory, wazuh_log_monitor, time_travel=True, min_timeout=3, triggers_event=trigger)


@pytest.mark.parametrize('directory,  tags_to_apply', [
    (os.path.join('/', 'nfs-mount-point'), {'skip_nfs'})
])
@patch('wazuh_testing.fim.modify_file_inode')
def test_skip_nfs(modify_inode_mock, directory, tags_to_apply, configure_nfs, get_configuration, configure_environment,
                  restart_syscheckd, wait_for_syscheck_start):
    """Check if syscheckd skips nfs directories when setting 'skip_nfs="yes"'.

    This test assumes you have a nfs directory mounted on '/nfs-mount-point'. If you do not have one, use the fixture
    `configure_nfs`.

    Parameters
    ----------
    directory : str
        Directory that will be monitored.
    """
    def custom_callback(filename):
        def callback(line):
            match = callback_detect_event(line)
            if match and filename in match['data']['path']:
                return match

        return callback

    file = str(uuid.uuid1())
    check_apply_test(tags_to_apply, get_configuration['tags'])
    trigger = get_configuration['metadata']['skip'] == 'no'

    try:
        regular_file_cud(directory, wazuh_log_monitor, file_list=[file], time_travel=True, min_timeout=3,
                         triggers_event=trigger, callback=custom_callback(file))

    finally:
        delete_file(directory, file)
