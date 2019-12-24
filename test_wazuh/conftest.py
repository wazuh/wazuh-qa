# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.tools import LOG_FILE_PATH, delete_sockets, FileMonitor, truncate_file, control_service, \
    SocketController, SocketMonitor, check_daemon_status

ALL = set("darwin linux win32 sunos5".split())


def pytest_runtest_setup(item):
    supported_platforms = ALL.intersection(mark.name for mark in item.iter_markers())
    plat = sys.platform
    if supported_platforms and plat not in supported_platforms:
        pytest.skip("Cannot run on platform {}".format(plat))
    # Consider only first mark
    levels = [mark.kwargs['level'] for mark in item.iter_markers(name="tier")]
    if levels and len(levels) > 0:
        tier = item.config.getoption("--tier")
        if tier is not None and tier != levels[0]:
            pytest.skip(f"test requires tier level {levels[0]}")
        elif item.config.getoption("--tier-minimum") > levels[0]:
            pytest.skip(f"test requires a minimum tier level {levels[0]}")
        elif item.config.getoption("--tier-maximum") < levels[0]:
            pytest.skip(f"test requires a maximum tier level {levels[0]}")


@pytest.fixture(scope='module')
def restart_wazuh(get_configuration, request):
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Restart Wazuh and wait for the command to end
    control_service('restart')


def pytest_addoption(parser):
    parser.addoption(
        "--tier",
        action="store",
        metavar="level",
        default=None,
        type=int,
        help="only run tests with a tier level equal to 'level'",
    )
    parser.addoption(
        "--tier-minimum",
        action="store",
        metavar="minimum_level",
        default=-1,
        type=int,
        help="only run tests with a tier level less or equal than 'minimum_level'"
    )
    parser.addoption(
        "--tier-maximum",
        action="store",
        metavar="maximum_level",
        default=sys.maxsize,
        type=int,
        help="only run tests with a tier level less or equal than 'minimum_level'"
    )


def pytest_configure(config):
    # register an additional marker
    config.addinivalue_line(
        "markers", "tier(level): mark test to run only if match tier level"
    )


@pytest.fixture(scope='module')
def configure_environment_standalone_daemons(request):
    """Configure a custom environment for testing with specific Wazuh daemons only. Stopping wazuh-service is needed."""

    def clear_logs():
        """Clear all Wazuh logs"""
        logs_path = '/var/ossec/logs'
        for root, dirs, files in os.walk(logs_path):
            for file in files:
                try:
                    open(os.path.join(root, file), 'w').close()
                except FileNotFoundError:
                    pass

    def remove_logs():
        """Remove all Wazuh logs"""
        logs_path = '/var/ossec/logs'
        for root, dirs, files in os.walk(logs_path):
            for file in files:
                os.remove(os.path.join(root, file))

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running=False)

    # Remove all remaining Wazuh sockets
    delete_sockets()

    # Start selected daemons in debug mode and ensure they are running
    for daemon in getattr(request.module, 'used_daemons'):
        control_service('start', daemon=daemon, debug_mode=True)
        check_daemon_status(running=True, daemon=daemon)

    # Clear all Wazuh logs
    clear_logs()

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    yield

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    # Stop wazuh-service
    control_service('stop')

    # Remove all remaining Wazuh sockets
    delete_sockets()

    # Remove all Wazuh logs
    remove_logs()


@pytest.fixture(scope='module')
def create_unix_sockets(request):
    """Create the specified unix sockets for the tests."""
    monitored_sockets_params = getattr(request.module, 'monitored_sockets_params')
    receiver_sockets_params = getattr(request.module, 'receiver_sockets_params')

    # Create the unix sockets
    monitored_sockets, receiver_sockets = list(), list()
    for path_, protocol in monitored_sockets_params:
        monitored_sockets.append(SocketMonitor(path=path_, connection_protocol=protocol))
    for path_, protocol in receiver_sockets_params:
        receiver_sockets.append(SocketController(path=path_, connection_protocol=protocol))

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'receiver_sockets', receiver_sockets)

    yield

    # Close the sockets gracefully
    for monitored_socket, receiver_socket in zip(monitored_sockets, receiver_sockets):
        monitored_socket.close()
        receiver_socket.close()
