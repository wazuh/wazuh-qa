import os
import pytest
import subprocess

from wazuh_testing.tools import WAZUH_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# variables

ANALYSISD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue')
analysisd_path =  os.path.join(WAZUH_PATH,'bin', 'wazuh-analysisd')
command_exec = f'{analysisd_path} -t'



def test_queue_socket_status():
    current_inode_file = os.stat(ANALYSISD_SOCKET).st_ino
    current_status_time = os.path.getmtime(ANALYSISD_SOCKET)

    # Updating Analysisd
    run = subprocess.Popen(['/bin/bash', '-c', command_exec])
    run.communicate()
 
    try:
        assert current_inode_file == os.stat(ANALYSISD_SOCKET).st_ino
    except AssertionError:
        raise AssertionError(f'The Inode value for the socket  {ANALYSISD_SOCKET} has changed')

    try:
        assert current_status_time == os.path.getmtime(ANALYSISD_SOCKET)
    except AssertionError:
        raise AssertionError(f'The Filetime value for the socket {ANALYSISD_SOCKET} has changed')
