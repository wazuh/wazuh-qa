import pytest
from wazuh_testing.tools import LOG_FILE_PATH, CLIENT_KEYS_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service
from authd import DAEMON_NAME


AUTHD_STARTUP_TIMEOUT = 30


def truncate_client_keys_file():
    """
    Cleans any previous key in client.keys file.
    """
    try:
        control_service("stop", DAEMON_NAME)
    except Exception:
        pass
    truncate_file(CLIENT_KEYS_PATH)


@pytest.fixture(scope='function')
def clean_client_keys_file_function():
    """
    Cleans any previous key in client.keys file at function scope.
    """
    truncate_client_keys_file()


@pytest.fixture(scope='module')
def clean_client_keys_file_module():
    """
    Cleans any previous key in client.keys file at module scope.
    """
    truncate_client_keys_file()


@pytest.fixture(scope='module')
def restart_authd(get_configuration):
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='function')
def restart_authd_function():
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='function')
def stop_authd_function():
    """
    Stop Authd.
    """
    control_service("stop", daemon=DAEMON_NAME)


@pytest.fixture(scope='module')
def wait_for_authd_startup_module(get_configuration):
    """Wait until authd has begun"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                      callback=make_callback('Accepting connections on port 1515', prefix=AUTHD_DETECTOR_PREFIX,
                                             escape=True),
                      error_message='Authd doesn´t started correctly.')


@pytest.fixture(scope='function')
def wait_for_authd_startup_function():
    """Wait until authd has begun with function scope"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                      callback=make_callback('Accepting connections on port 1515', prefix=AUTHD_DETECTOR_PREFIX,
                                             escape=True),
                      error_message='Authd doesn´t started correctly.')


@pytest.fixture(scope='module')
def tear_down():
    """
    Roll back the daemon and client.keys state after the test ends.
    """
    yield
    # Stop Wazuh
    control_service('stop')
    truncate_file(CLIENT_KEYS_PATH)
