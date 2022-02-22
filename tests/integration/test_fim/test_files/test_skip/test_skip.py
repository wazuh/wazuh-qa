'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if the 'wazuh-syscheckd' daemon skips
       the scans on the special directories of Linux systems ('/dev', '/proc', '/sys', and NFS folders),
       using the 'skip_' tags for this purpose.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux

os_version:
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#skip-dev
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#skip-nfs
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#skip-proc
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#skip-sys
    - https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_skip
'''
import os
import shutil
import subprocess
import uuid
from datetime import timedelta
from unittest.mock import patch

import distro
import pytest
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

def test_skip_proc(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon skips the Linux '/proc' directory at scanning when
                 the 'skip_proc' tag is set to 'yes'. For this purpose, the test will monitor a PID folder
                 in the '/proc' directory. To generate the PID folder, it will call a script that contains
                 an endless loop to create the process that adds that folder to the '/proc' directory. Then,
                 the test adds to the main configuration the PID folder to monitor, and finally, it will verify
                 that the FIM 'added' event related to the PID folder ('skip_proc == no') or the FIM 'integrity'
                 event ('skip_proc == yes') is generated.

    wazuh_min_version: 4.2.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that no FIM events are generated from a monitored folder inside the '/proc' directory when
          the 'skip_proc' tag is set to 'yes' and vice versa.

    input_description: A test case (skip_proc) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon, and these are
                       combined with the testing directory to be monitored defined in the module.
                       To generate the directory to monitor in '/proc', the 'proc.py' script is used,
                       which runs an endless loop to keep the PID active.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events if 'skip_proc == no')
        - r'.*Sending integrity control message: (.+)$' (if 'skip_sys == yes')

    tags:
        - scheduled
        - time_travel
    '''
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


def test_skip_sys(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon skips the Linux '/sys' directory at scanning when the
                 'skip_sys' tag is set to 'yes'. For this purpose, the test will monitor the 'module/isofs'
                 folder in the '/sys' directory. That folder is created by the 'isofs' module, so if it
                 does not exist, it must be load before the test run. Then, it will remove the 'isofs' folder
                 by unloading the 'isofs' module, and finally, it will verify that the FIM 'deleted' event
                 related to the 'isofs' folder ('skip_proc == no') or the FIM 'integrity' event
                 ('skip_proc == yes') is generated.

    wazuh_min_version: 4.2.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that no FIM events are generated from a monitored folder inside the '/sys' directory when
          the 'skip_sys' tag is set to 'yes' and vice versa.

    input_description: A test case (skip_sys) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and the testing
                       directory to be monitored.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('deleted' events if 'skip_sys == no')
        - r'.*Sending integrity control message: (.+)$' (if 'skip_sys == yes')

    tags:
        - scheduled
        - time_travel
    '''
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
def test_skip_dev(modify_inode_mock, directory, tags_to_apply, get_configuration, configure_environment,
                  restart_syscheckd,
                  wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon skips the Linux '/dev' directory at scanning when the
                 'skip_dev' tag is set to 'yes'. For this purpose, the test will monitor the '/dev' directory.
                 Then, it will make file operations inside it, and finally, the test will verify that FIM events
                 from the '/dev' folder are generated or not depending on the value of the 'skip_dev' tag.

    wazuh_min_version: 4.2.0

    parameters:
        - modify_inode_mock:
            type: None
            brief: Change the inode of a file in Linux systems.
        - directory:
            type: str
            brief: Path to the testing directory that will be monitored.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that no FIM events are generated from the '/dev' directory when
          the 'skip_dev' tag is set to 'yes' and vice versa.

    input_description: A test case (skip_dev) is contained in external YAML file (wazuh_conf.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and the testing
                       directory to be monitored.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events if 'skip_sys == no')

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    trigger = get_configuration['metadata']['skip'] == 'no'

    regular_file_cud(directory, wazuh_log_monitor, time_travel=True, min_timeout=3, triggers_event=trigger)


@pytest.mark.parametrize('directory,  tags_to_apply', [
    (os.path.join('/', 'nfs-mount-point'), {'skip_nfs'})
])
@pytest.mark.skip(reason="It will be blocked by #2174 and #2186, when it was solve we can enable again this test")
@patch('wazuh_testing.fim.modify_file_inode')
def test_skip_nfs(modify_inode_mock, directory, tags_to_apply, configure_nfs, get_configuration, configure_environment,
                  restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon skips NFS directories at scanning when the 'skip_nfs' tag
                 is set to 'yes'. For this purpose, the test will create and monitor a NFS mount point. Then,
                 it will make file operations inside it, and finally, the test will verify that FIM events
                 from the NFS folder are generated or not depending on the value of the 'skip_nfs' tag.

    wazuh_min_version: 4.2.0

    parameters:
        - modify_inode_mock:
            type: None
            brief: Change the inode of a file in Linux systems.
        - directory:
            type: str
            brief: Path to the testing directory that will be monitored.
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - configure_nfs:
            type: fixture
            brief: Call NFS scripts to create and configure a NFS mount point.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that no FIM events are generated from an NFS monitored directory when
          the 'skip_nfs' tag is set to 'yes' and vice versa.

    input_description: A test case (skip_nfs) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and
                       the testing directory to be monitored. To generate the NFS directory to monitor,
                       the 'configure_nfs.sh' script is used, which install, configure, and create a
                       mount point using NFS. To remove the mount point, the 'remove_nfs.sh' script is used.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events if 'skip_nfs == no')

    tags:
        - scheduled
        - time_travel
    '''
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
