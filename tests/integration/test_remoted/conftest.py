# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import shutil
import subprocess as sb
import os
import pytest
from wazuh_testing.remote import callback_detect_remoted_started, new_agent_group, REMOTED_GLOBAL_TIMEOUT, \
                                 remove_agent_group
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
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


@pytest.fixture(scope="module")
def remove_shared_files():
    """Temporary removes txt files from default agent group shared files"""

    source_dir = os.path.join(WAZUH_PATH, 'etc', 'shared', 'default')
    target_dir = os.path.join(WAZUH_PATH, 'etc', 'default.backup')

    os.mkdir(target_dir)

    file_names = os.listdir(source_dir)

    for file_name in file_names:
        if 'txt' in file_name:
            shutil.move(os.path.join(source_dir, file_name), target_dir)

    yield

    for file_name in file_names:
        if 'txt' in file_name:
            shutil.move(os.path.join(target_dir, file_name), source_dir)

    os.removedirs(target_dir)


@pytest.fixture(scope="module")
def wait_for_remoted_start_log(get_configuration):
    """Checks if remoted start callback appears"""
    remoted_start_monitor = FileMonitor(LOG_FILE_PATH)
    remoted_start_monitor.start(timeout=REMOTED_GLOBAL_TIMEOUT,
                                callback=callback_detect_remoted_started('.*', '.*', '.*'),
                                error_message="The 'Started (pid...' remoted log didn't appear")
