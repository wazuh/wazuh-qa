# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import subprocess as sb

import pytest
from wazuh_testing.remote import remove_agent_group, new_agent_group
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

DAEMON_NAME = "wazuh-remoted"


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
def create_agent_group(group_name='testing_group'):
    """Temporary creates a new agent group for testing purpose, must be run only on Managers."""

    new_agent_group(group_name)

    yield

    remove_agent_group(group_name)