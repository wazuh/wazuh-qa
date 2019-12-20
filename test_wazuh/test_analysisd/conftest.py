# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import shutil

import pytest

from wazuh_testing.tools import control_service
from wazuh_testing.tools import SocketMonitor, SocketController


@pytest.fixture(scope='module')
def configure_local_rules(get_configuration, request):
    """Configure a custom rule in local_rules.xml for testing. Restart Wazuh is needed for applying the configuration."""

    # save current configuration
    shutil.copy('/var/ossec/etc/rules/local_rules.xml', '/var/ossec/etc/rules/local_rules.xml.cpy')

    # configuration for testing
    file_test = str(get_configuration)
    shutil.copy(file_test, '/var/ossec/etc/rules/local_rules.xml')

    # restart wazuh service
    control_service('restart')

    yield

    # restore previous configuration
    shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy', '/var/ossec/etc/rules/local_rules.xml')

    # restart wazuh service
    control_service('restart')


@pytest.fixture(scope='module')
def create_unix_sockets(request):
    monitored_sockets_params = getattr(request, 'monitored_sockets_params')
    receiver_sockets_params = getattr(request, 'receiver_sockets_params')

    monitored_sockets, receiver_sockets = list(), list()
    for path_, protocol in monitored_sockets_params:
        monitored_sockets.append(SocketMonitor(path=path_, connection_protocol=protocol))
    for path_, protocol in receiver_sockets_params:
        receiver_sockets.append(SocketController(path=path_, connection_protocol=protocol))

    setattr(request, 'monitored_sockets', monitored_sockets)
    setattr(request, 'receiver_sockets', receiver_sockets)

    yield

    for monitored_socket, receiver_socket in monitored_sockets, receiver_sockets:
        monitored_socket.close()
        receiver_socket.close()
