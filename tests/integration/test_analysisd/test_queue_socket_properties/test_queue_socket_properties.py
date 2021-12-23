import os
import pytest
import subprocess

from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# variables

ANALYSISD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue')
analysisd_path =  os.path.join(WAZUH_PATH,'bin', 'wazuh-analysisd')
command_exec = f'{analysisd_path} -t'

# Fixtures

@pytest.fixture(scope="function")
def socket_file_properties():
    return os.stat(ANALYSISD_SOCKET).st_ino, os.path.getmtime(ANALYSISD_SOCKET)

@pytest.fixture(scope="function")
def run_analysisd_test_config():
     # restart analysisd daemon
    control_service('restart', daemon='wazuh-analysisd')
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    # run analysisd test configuration mode
    run = subprocess.Popen(['/bin/bash', '-c', command_exec])
    run.communicate()
    

def test_queue_socket_properties(socket_file_properties, run_analysisd_test_config):
    # Check if analysisd daemon is running 
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    current_inode_file, current_status_time = socket_file_properties

    run_analysisd_test_config

    assert current_inode_file == os.stat(ANALYSISD_SOCKET).st_ino, \
            f"The Inode value for the socket  {ANALYSISD_SOCKET} has changed"

    assert current_status_time == os.path.getmtime(ANALYSISD_SOCKET), \
            f"The Filetime value for the socket {ANALYSISD_SOCKET} has changed"
