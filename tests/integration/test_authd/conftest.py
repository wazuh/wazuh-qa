import pytest
from wazuh_testing.tools import LOG_FILE_PATH, CLIENT_KEYS_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

DAEMON_NAME = 'wazuh-authd'
AUTHD_STARTUP_TIMEOUT = 30

@pytest.fixture(scope='function')
def wait_for_authd_startup(request):
    """Wait until authd has begun"""
    def callback_authd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT, callback=callback_authd_startup)


@pytest.fixture(scope='function')
def restart_authd(get_configuration, request):
    """Reset log file and start a new monitor."""
    control_service('stop', daemon=DAEMON_NAME)
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon=DAEMON_NAME)


def clean_client_keys_file():
    """
    Cleans any previus key in client.keys file.
    """
    truncate_file(CLIENT_KEYS_PATH)

    yield

    truncate_file(CLIENT_KEYS_PATH)


@pytest.fixture(scope='function')
def clean_client_keys_file_function():
    """
    Cleans any previus key in client.keys file at function scope.
    """
    clean_client_keys_file()


@pytest.fixture(scope='module')
def clean_client_keys_file_module():
    """
    Cleans any previus key in client.keys file at module scope.
    """
    clean_client_keys_file()

@pytest.fixture(scope='module')
def restart_authd(get_configuration, request):
    #TODO: Make only Authd restarts
    """
    Restart Authd.
    """

    #control_service('restart', daemon='wazuh-authd')
    control_service('restart')

    yield
    #control_service('stop', daemon='wazuh-authd')
    control_service('stop')
