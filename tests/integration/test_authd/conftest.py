import pytest
import os
import yaml
from wazuh_testing.tools import LOG_FILE_PATH, CLIENT_KEYS_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import write_wazuh_conf, get_wazuh_conf, set_section_wazuh_conf,\
                                              load_wazuh_configurations
from wazuh_testing.tools.services import control_service, check_daemon_status, delete_dbs
from wazuh_testing.tools.monitoring import QueueMonitor


from wazuh_testing.authd import DAEMON_NAME


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
    try:
        control_service("restart", daemon=DAEMON_NAME)
    except Exception:
        pass


@pytest.fixture(scope='function')
def restart_authd_function():
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    try:
        control_service("restart", daemon=DAEMON_NAME)
    except Exception:
        pass


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
    control_service('start')


def create_force_config_block(param, config_path):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(os.path.dirname(config_path), 'temp.yaml')

    with open(config_path, 'r') as conf_file:
        temp_conf_file = yaml.safe_load(conf_file)
        for elem in param:
            temp_conf_file[0]['sections'][0]['elements'].append(elem)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


@pytest.fixture(scope='function')
def format_configuration(get_current_test_case, request):
    """
    Get configuration block from current test case
    """
    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})

    # Configuration for testing
    temp = create_force_config_block(configuration, request.module.configurations_path)
    conf = load_wazuh_configurations(temp, test_name)
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])

    return test_config


@pytest.fixture(scope='function')
def override_authd_force_conf(format_configuration):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    # Save current configuration
    backup_config = get_wazuh_conf()

    # Set new configuration
    write_wazuh_conf(format_configuration)

    yield

    # Restore previous configuration
    write_wazuh_conf(backup_config)


@pytest.fixture(scope='module')
def configure_sockets_environment_wazuh_control(request):
    """Configure environment for sockets and MITM"""
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')
    log_monitor_paths = getattr(request.module, 'log_monitor_paths')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running=False, use_wazuh_control=True)

    monitored_sockets = list()
    mitm_list = list()
    log_monitors = list()

    # Truncate logs and create FileMonitors
    for log in log_monitor_paths:
        truncate_file(log)
        log_monitors.append(FileMonitor(log))

    # Start selected daemons and monitored sockets MITM
    for daemon, mitm, daemon_first in monitored_sockets_params:
        not daemon_first and mitm is not None and mitm.start()
        control_service('start', daemon=daemon, debug_mode=True)
        check_daemon_status(
            running=True,
            daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else None,
            use_wazuh_control=True
        )
        daemon_first and mitm is not None and mitm.start()
        if mitm is not None:
            monitored_sockets.append(QueueMonitor(queue_item=mitm.queue))
            mitm_list.append(mitm)

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'log_monitors', log_monitors)

    yield

    # Stop daemons and monitored sockets MITM
    for daemon, mitm, _ in monitored_sockets_params:
        mitm is not None and mitm.shutdown()
        control_service('stop', daemon=daemon)
        check_daemon_status(
            running=False,
            daemon=daemon,
            extra_sockets=[mitm.listener_socket_address] if mitm is not None and mitm.family == 'AF_UNIX' else None,
            use_wazuh_control=True
        )

    # Delete all db
    delete_dbs()

    control_service('start')
