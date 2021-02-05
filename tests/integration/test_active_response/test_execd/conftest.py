import os
import pytest
import socket
import ssl
import platform

from configobj import ConfigObj
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file

AR_FOLDER = 'active-response' if platform.system() == 'Windows' else 'logs'
AR_LOG_FILE_PATH = os.path.join(WAZUH_PATH, AR_FOLDER, 'active-responses.log')


def get_current_version():
    """
    Get version of Wazuh installed
    """
    if platform.system() == 'Linux':
        config_file_path = os.path.join(WAZUH_PATH, 'etc', 'ossec-init.conf')
        _config = ConfigObj(config_file_path)
        return _config['VERSION']

    else:
        version = None
        with open(os.path.join(WAZUH_PATH, 'VERSION'), 'r') as f:
            version = f.read()
            version = version[:version.rfind('\n')]
        return version


@pytest.fixture(scope="session")
def set_ar_conf_mode():
    """
    Configure Active Responses used in tests
    """
    folder = 'shared' if platform.system() == 'Windows' else 'etc/shared'
    local_int_conf_path = os.path.join(WAZUH_PATH, folder, 'ar.conf')
    debug_line = "restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n" \
                 "firewall-drop0 - firewall-drop - 0\nfirewall-drop5 - firewall-drop - 5\n"
    with open(local_int_conf_path, 'w') as local_file_write:
        local_file_write.write('\n'+debug_line)
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return


@pytest.fixture(scope="session")
def set_debug_mode():
    """
    Set execd daemon in debug mode
    """
    folder = '' if platform.system() == 'Windows' else 'etc'
    local_int_conf_path = os.path.join(WAZUH_PATH, folder, 'local_internal_options.conf')
    debug_line = 'windows.debug=2\n' if platform.system() == 'Windows' else 'execd.debug=2\n'
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)


def wait_received_message_line(line):
    """
    Callback function to wait for the Received Active Response message
    """
    return True if "DEBUG: Received message: " in line else None


def wait_start_message_line(line):
    """
    Callback function to wait for the Starting Active Response message
    """
    return True if "Starting" in line else None


def wait_ended_message_line(line):
    """
    Callback function to wait for the Ended Active Response message
    """
    return True if "Ended" in line else None


def clean_logs():
    """
    Clean log file
    """
    truncate_file(LOG_FILE_PATH)
    truncate_file(AR_LOG_FILE_PATH)


@pytest.fixture(scope="session")
def test_version():
    """
    Validate Wazuh version
    """
    if get_current_version() < "v4.2.0":
        raise AssertionError("The version of the agent is < 4.2.0")


def start_log_monitoring(monitor, callback, timeout=60):
    """
    Monitor log and wait for message defined in callback
    """
    try:
        monitor.start(timeout, callback)
    except TimeoutError:
        raise AssertionError("Message took too much!")
