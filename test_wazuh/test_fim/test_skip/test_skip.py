# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess
from datetime import timedelta

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_detect_integrity_event,
                               regular_file_cud, detect_initial_scan, callback_detect_event)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, TimeMachine,
                                 set_section_wazuh_conf, restart_wazuh_with_new_conf)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir = os.path.join('/', 'testdir1')
test_directories = [testdir]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

def change_conf(dir_value):
    return load_wazuh_configurations(configurations_path, __name__,
                                     params=[{'SKIP': 'yes', 'DIRECTORY': dir_value},
                                             {'SKIP': 'no', 'DIRECTORY': dir_value},
                                             ],
                                     metadata=[{'skip': 'yes', 'directory': dir_value},
                                               {'skip': 'no', 'directory': dir_value},
                                               ]
                                     )


configurations = change_conf(testdir)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='session')
def configure_nfs():
    """ Call NFS scripts to create and configure a NFS mount point """
    path = os.path.dirname(os.path.abspath(__file__))
    subprocess.call([f'{path}/data/configure_nfs.sh'])
    yield
    # remove nfs
    subprocess.call([f'{path}/data/remove_nfs.sh'])
    shutil.rmtree(os.path.join('/', 'media', 'nfs-folder'), ignore_errors=True)


# tests

@pytest.mark.parametrize('directory,  tags_to_apply', [
    (os.path.join('/', 'proc'), {'skip_proc'}),
    (os.path.join('/', 'sys', 'video'), {'skip_sys'}),
    (os.path.join('/', 'dev'), {'skip_dev'}),
    (os.path.join('/', 'nfs-mount-point'), {'skip_nfs'})
])
def test_skip(directory, tags_to_apply,
              get_configuration, configure_environment, configure_nfs,
              restart_syscheckd, wait_for_initial_scan):
    """ Check if syscheck is skipping the directory based on its skip configuration

    :param directory: Directory that will be monitored. We only use it on skip_dev and skip_nfs
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if get_configuration['metadata']['skip'] == 'yes':
        trigger = False
    else:
        trigger = True

    if tags_to_apply == {'skip_proc'}:
        if trigger:
            proc = subprocess.Popen(["python3", f"{os.path.dirname(os.path.abspath(__file__))}/data/proc.py"])
            # Change configuration, monitoring the PID path in /proc
            new_conf = change_conf(f'/proc/{proc.pid}')
            new_ossec_conf = []
            # Get new skip_proc configuration
            for conf in new_conf:
                if conf['metadata']['skip'] == 'no' and conf['tags'] == ['skip_proc']:
                    new_ossec_conf = set_section_wazuh_conf(conf.get('section'),
                                                            conf.get('elements'))
            restart_wazuh_with_new_conf(new_ossec_conf)
            proc_monitor = FileMonitor(LOG_FILE_PATH)
            detect_initial_scan(proc_monitor)

            # Do not expect any 'Sending event'
            with pytest.raises(TimeoutError):
                proc_monitor.start(timeout=3, callback=callback_detect_event)

            TimeMachine.travel_to_future(timedelta(hours=13))

            found_event = False
            while not found_event:
                event = proc_monitor.start(timeout=5, callback=callback_detect_event).result()
                if f'/proc/{proc.pid}/' in event['data'].get('path'):
                    found_event = True

            # Kill the process
            subprocess.Popen(["kill", "-9", str(proc.pid)])

        else:
            with pytest.raises(TimeoutError):
                wazuh_log_monitor.start(timeout=3, callback=callback_detect_integrity_event)

    elif tags_to_apply == {'skip_sys'}:
        if trigger:
            # If /sys/module/video does not exist, use 'modprobe video'
            assert os.path.exists('/sys/module/video'), f'/sys/module/video does not exist'
            # Do not expect any 'Sending event'
            with pytest.raises(TimeoutError):
                wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
            # Remove module video and travel to future to check alerts
            subprocess.Popen(["modprobe", "-r", "video"])
            TimeMachine.travel_to_future(timedelta(hours=13))
            # Detect at least one 'delete' event in /sys/module/video path
            event = wazuh_log_monitor.start(timeout=5, callback=callback_detect_event).result()
            assert event['data'].get('type') == 'deleted' and '/sys/module/video' in event['data'].get('path'), \
                f'Sys event not detected'
            # Restore module video
            subprocess.Popen(["modprobe", "video"])
        else:
            with pytest.raises(TimeoutError):
                wazuh_log_monitor.start(timeout=3, callback=callback_detect_integrity_event)
    else:
        regular_file_cud(directory, wazuh_log_monitor,
                         time_travel=True,
                         min_timeout=3, triggers_event=trigger)
