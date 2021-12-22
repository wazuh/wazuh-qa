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

# Fixture 
def configure_analysisd_queue_socket():
     # restart analysisd daemon
    control_service('restart', daemon='wazuh-analysisd')
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    # Updating Analysisd 
    run = subprocess.Popen(['/bin/bash', '-c', command_exec])
    run.communicate()
    
def test_queue_socket_properties():
    # Check if analysisd daemon is running 
    if check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd') is not True:
        control_service('start', daemon='wazuh-analysisd')

    current_inode_file = os.stat(ANALYSISD_SOCKET).st_ino
    current_status_time = os.path.getmtime(ANALYSISD_SOCKET)

    configure_analysisd_queue_socket()

    assert current_inode_file == os.stat(ANALYSISD_SOCKET).st_ino, \
            f"The Inode value for the socket  {ANALYSISD_SOCKET} has changed"

    assert current_status_time == os.path.getmtime(ANALYSISD_SOCKET), \
            f"The Filetime value for the socket {ANALYSISD_SOCKET} has changed"