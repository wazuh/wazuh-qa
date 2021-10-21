'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM ends the synchronization
       with the manager at the expected time set in the 'interval' and the 'response_timeout' tags.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 2

modules:
    - fim

components:
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux

os_version:
    - Arch Linux
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
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os
import sys
import time
from datetime import datetime, timedelta

import psutil
import pytest
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_end_scan, callback_detect_synchronization, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine, time_to_timedelta

if sys.platform == "linux":
    import paramiko

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2), pytest.mark.server]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations_path = os.path.join(test_data_path, 'wazuh_response_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir1')]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
response_timeouts = ['10', '10m', '10h', '10d', '10w']
sync_interval = ['20', '20m', '20h', '20d', '20w']

list_ = []
for response in response_timeouts:
    for sync in sync_interval:
        if time_to_timedelta(sync) > time_to_timedelta(response):
            list_.append({'RESPONSE_TIMEOUT': response, 'INTERVAL': sync})

# configurations
p, m = generate_params(apply_to_all=list_, modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('num_files', [1, 100])
def test_response_timeout(num_files, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the agent synchronization ends at the expected time set in the 'interval'
                 and the 'response_timeout' tags, being 'interval' greater than 'response_timeout'.
                 To accomplish this, a connection with a Wazuh agent (Linux-based) must be established
                 via SSH using Paramiko. All operations will take place on the Agent side. For this
                 purpose, the test will monitor a testing directory and create multiple files inside it.
                 Then, it will wait until the first synchronization ends and travel in time to a datetime
                 when synchronization should not happen to ensure there is no synchronization at this time.
                 Finally, the test will travel in time to a datetime when synchronization must occur, and
                 wait until the next synchronization is detected.

    wazuh_min_version: 4.2.0

    parameters:
        - num_files:
            type: int
            brief: Number of files to create within the testing directory.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that FIM sync events are generated at the specified intervals.
        - Verify that the synchronization ends before the response timeout.
        - Verify that no FIM sync events are generated before the specified intervals.

    input_description: A test case (response_timeout) is contained in external YAML file
                       (wazuh_response_conf.yaml) which includes configuration settings
                       for the 'wazuh-syscheckd' daemon. That is combined with the
                       testing directory to be monitored defined in this module.

    expected_output:
        - r'.*#!-fim_registry dbsync no_data (.+)'
        - r'.*Sending integrity control message'

    tags:
        - scheduled
        - time_travel
    '''
    def overwrite_agent_conf_file():
        cmd = "sudo sed -i ':a;N;$!ba;s|<synchronization>.*</synchronization>|<synchronization>\
            <enabled>yes</enabled>\
                <interval>" + str(sync_interval) + "</interval>\
                    <response_timeout>" + str(response_timeout) + "</response_timeout>\
                        </synchronization>|g' /var/ossec/etc/ossec.conf"
        ssh.exec_command(cmd)

    def wait_agent_initial_scan(time_out=60):
        truncate_agent_log()
        start_time = datetime.now()
        while datetime.now() < start_time + timedelta(seconds=time_out):
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo cat /var/ossec/logs/ossec.log")
            for line in ssh_stdout.read().decode('ascii').splitlines():
                if callback_detect_end_scan(line):
                    return
        pytest.fail("No 'File integrity monitoring scan ended.' was found on ossec.log.")

    def create_files_in_agent():
        ssh.exec_command("sudo systemctl stop wazuh-agent")
        ssh.exec_command("sudo mkdir " + DIR_NAME)
        ssh.exec_command("sudo touch " + DIR_NAME + "/testfile{0.." + str(num_files) + "}")

        purge_manager_db()

        ssh.exec_command("sudo systemctl start wazuh-agent")

    def purge_manager_db():
        for proc in psutil.process_iter(attrs=['name']):
            if proc.name() == "wazuh-db":
                proc.terminate()

        os.system("rm -f /var/ossec/queue/db/00{1..9}.db*")
        os.system("/var/ossec/bin/wazuh-db")
        time.sleep(5)

    def detect_synchronization_start(time_out=1):
        start_time = datetime.now()
        while datetime.now() < start_time + timedelta(seconds=time_out):
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo cat /var/ossec/logs/ossec.log")
            for line in ssh_stdout.read().decode('ascii').splitlines():
                if callback_detect_synchronization(line):
                    return extract_datetime(str(line))
        return None

    def wait_agent_dbsync_finish():
        previous_time = datetime.now()
        while datetime.now() - previous_time < timedelta(seconds=3):
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo cat /var/ossec/logs/ossec.log")
            for line in ssh_stdout.read().decode('ascii').splitlines():
                if "syscheck dbsync" in line:
                    previous_time = datetime.now()
            truncate_agent_log()
        return datetime.now()

    def wait_agent_integrity_control():
        previous_time = datetime.now()
        while datetime.now() - previous_time < timedelta(seconds=1):
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo cat /var/ossec/logs/ossec.log")
            for line in ssh_stdout.read().decode('ascii').splitlines():
                if "Sending integrity control message" in line:
                    previous_time = datetime.now()
                elif callback_detect_synchronization(line):
                    pytest.fail("No new synchronization process should start until `integrity control message` ends.")
            truncate_agent_log()

    def truncate_agent_log():
        ssh.exec_command("sudo truncate -s 0 " + LOG_PATH)

    def extract_datetime(line):
        return datetime.strptime(line[0:19], '%Y/%m/%d %H:%M:%S')

    def update_agent_datetime():
        now = datetime.now()
        year = str(now.year)
        month = str(now.month)
        day = str(now.day)
        hour = str(now.hour)
        minute = str(now.minute)
        second = str(now.second)
        timedatectl_cmd = "sudo timedatectl set-time '" + year + "-" + month + "-" + day + " " + hour + ":" + minute + \
                          ":" + second + "'"
        ssh.exec_command(timedatectl_cmd)

    # Check if the test should be skipped
    check_apply_test({'response_timeout'}, get_configuration['tags'])

    # Variables
    LOG_PATH = "/var/ossec/logs/ossec.log"
    DIR_NAME = "/testdir1"
    AGENT_IP = "172.19.0.201"
    USERNAME = "vagrant"
    PASSWORD = "vagrant"
    response_timeout = get_configuration['metadata']['response_timeout']
    sync_interval = get_configuration['metadata']['interval']

    # Connect to the agent
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=AGENT_IP, username=USERNAME, password=PASSWORD)

    # Setup agent
    overwrite_agent_conf_file()
    update_agent_datetime()
    create_files_in_agent()
    wait_agent_initial_scan()

    # Check if first synchronization has started
    time_first_synchronization = detect_synchronization_start()
    if time_first_synchronization is None:
        pytest.fail("No synchronization was detected.")

    # Wait until synchronization ends
    time_after_dbsync = wait_agent_dbsync_finish()
    wait_agent_integrity_control()
    truncate_agent_log()

    # Determines when the next synchronization should occur
    max_next_synchronization = max(
        time_first_synchronization + time_to_timedelta(sync_interval),
        time_after_dbsync + time_to_timedelta(response_timeout)
    )

    # Calculate a datetime when the next synchronization should NOT happen
    min_next_synchronization = min(
        time_first_synchronization + time_to_timedelta(sync_interval),
        time_after_dbsync + time_to_timedelta(response_timeout)
    )

    # Travels in time to a datetime when synchronization should NOT happen, if needed
    if min_next_synchronization > datetime.now() and sync_interval != response_timeout:
        TimeMachine.travel_to_future(min_next_synchronization - datetime.now())
        update_agent_datetime()

    # Ensure there is no synchronization at this time.
    if detect_synchronization_start() is not None:
        pytest.fail("No synchronization should happen at this time.")

    # Travels in time to a datetime when synchronization MUST ocurr
    TimeMachine.travel_to_future(max_next_synchronization - datetime.now())
    update_agent_datetime()

    # Wait until next synchronization is detected
    if detect_synchronization_start(time_out=10) is None:
        pytest.fail("No synchronization was detected.")
