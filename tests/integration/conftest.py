# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, SocketController, SocketMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status, delete_sockets

ALL = set("darwin linux win32 sunos5".split())


def pytest_runtest_setup(item):
    supported_platforms = ALL.intersection(mark.name for mark in item.iter_markers())
    plat = sys.platform
    if supported_platforms and plat not in supported_platforms:
        pytest.skip("Cannot run on platform {}".format(plat))
    # Consider only first mark
    levels = [mark.kwargs['level'] for mark in item.iter_markers(name="tier")]
    if levels and len(levels) > 0:
        tiers = item.config.getoption("--tier")
        if tiers is not None and levels[0] not in tiers:
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
        action="append",
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
    parser.addoption(
        "--default-timeout",
        action="store",
        metavar="default_timeout",
        default=None,
        type=int,
        help="number of seconds that any timer will wait until an event is generated. This apply to all tests except"
             "those with a hardcoded timeout not depending on global_parameters.default_timeout "
             "variable from wazuh_testing package"
    )


def pytest_configure(config):
    # Register an additional marker
    config.addinivalue_line(
        "markers", "tier(level): mark test to run only if it matches tier level"
    )

    # Set default timeout only if it is passed through command line args
    default_timeout = config.getoption("--default-timeout")
    if default_timeout:
        global_parameters.default_timeout = default_timeout


@pytest.fixture(scope='module')
def configure_environment_standalone_daemons(request):
    """Configure a custom environment for testing with specific Wazuh daemons only. Stopping wazuh-service is needed."""

    def remove_logs():
        """Remove all Wazuh logs"""
        for root, dirs, files in os.walk(WAZUH_LOGS_PATH):
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
    truncate_file(LOG_FILE_PATH)

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    yield

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    # Stop selected daemons
    for daemon in getattr(request.module, 'used_daemons'):
        control_service('stop', daemon=daemon)

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
    for path_, protocol in receiver_sockets_params:
        receiver_sockets.append(SocketController(path=path_, connection_protocol=protocol))
    for path_, protocol in monitored_sockets_params:
        if (path_, protocol) in receiver_sockets_params:
            monitored_sockets.append(
                SocketMonitor(path=path_, connection_protocol=protocol,
                              controller=receiver_sockets[receiver_sockets_params.index((path_, protocol))]))
        else:
            monitored_sockets.append(SocketMonitor(path=path_, connection_protocol=protocol))

    setattr(request.module, 'monitored_sockets', monitored_sockets)
    setattr(request.module, 'receiver_sockets', receiver_sockets)

    yield

    # Close the sockets gracefully
    for monitored_socket, receiver_socket in zip(monitored_sockets, receiver_sockets):
        try:
            monitored_socket.close()
            receiver_socket.close()
        except OSError as e:
            if e.errno == 9:
                # Do not try to close the socket again if it was reused
                pass
