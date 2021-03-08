# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import os
import subprocess
import pytest
import subprocess as sb
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

DAEMON_NAME = "wazuh-remoted"
data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
default_agent_conf_path = os.path.join(data_path, 'agent.conf')

@pytest.fixture(scope='module')
def restart_remoted(get_configuration, request):
    # Reset ossec.log and start a new monitor
    control_service('stop', daemon=DAEMON_NAME)
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    try:
        control_service('start', daemon=DAEMON_NAME)
    except sb.CalledProcessError:
        pass


@pytest.fixture(scope="module")
def create_agent_group():
    """Temporary creates a new agent group for testing purpose, must be run only on Managers."""

    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-a", "-g", "testing_group"])

    with open(f"{WAZUH_PATH}/etc/shared/testing_group/agent.conf", "w") as agent_conf_file:
        with open(default_agent_conf_path, 'r') as configuration:
            agent_conf_file.write(configuration.read())

    yield

    sb.run([f"{WAZUH_PATH}/bin/agent_groups", "-q", "-r", "-g", "testing"])
