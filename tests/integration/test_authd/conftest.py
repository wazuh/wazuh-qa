import pytest
from wazuh_testing.tools import LOG_FILE_PATH, CLIENT_KEYS_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback
from wazuh_testing.tools.services import control_service

DAEMON_NAME = 'wazuh-authd'
AUTHD_STARTUP_TIMEOUT = 30


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
def restart_authd(get_configuration):
    """
    Restart Authd.
    """
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='module')
def wait_for_authd_startup(get_configuration):
    """Wait until authd has begun"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                              callback=make_callback('Accepting connections on port 1515', prefix='.*',
                                                     escape=True),
                              error_message='Authd doesn´t started correctly.')
