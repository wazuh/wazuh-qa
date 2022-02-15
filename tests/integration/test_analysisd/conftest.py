# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import shutil
import os

import pytest

from wazuh_testing.tools import (ALERT_FILE_PATH, LOG_FILE_PATH,
                                 WAZUH_UNIX_USER, WAZUH_UNIX_GROUP,
                                 CUSTOM_RULES_PATH)
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service
from wazuh_testing.mocking import create_mocked_agent, delete_mocked_agent
from wazuh_testing.tools.monitoring import FileMonitor


@pytest.fixture(scope='module')
def configure_local_rules(get_configuration, request):
    """Configure a custom rule in local_rules.xml for testing. Restart Wazuh is needed for applying the
    configuration. """

    # save current configuration
    shutil.copy('/var/ossec/etc/rules/local_rules.xml', '/var/ossec/etc/rules/local_rules.xml.cpy')

    # configuration for testing
    file_test = str(get_configuration)
    shutil.copy(file_test, '/var/ossec/etc/rules/local_rules.xml')

    yield

    # restore previous configuration
    shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy', '/var/ossec/etc/rules/local_rules.xml')


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""

    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)


@pytest.fixture(scope='module')
def configure_custom_rules(request, get_configuration):
    """Configure a syscollector custom rules for testing.
    Restarting wazuh-analysisd is required to apply this changes.
    """
    data_dir = getattr(request.module, 'data_dir')
    source_rule = os.path.join(data_dir, get_configuration['rule_file'])
    target_rule = os.path.join(CUSTOM_RULES_PATH, get_configuration['rule_file'])

    # copy custom rule with specific privileges
    shutil.copy(source_rule, target_rule)
    shutil.chown(target_rule, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)

    yield

    # remove custom rule
    os.remove(target_rule)


@pytest.fixture(scope='module')
def restart_analysisd():
    """wazuh-analysisd restart and log truncation"""
    required_logtest_daemons = ['wazuh-analysisd']

    truncate_file(ALERT_FILE_PATH)
    truncate_file(LOG_FILE_PATH)

    for daemon in required_logtest_daemons:
        control_service('restart', daemon=daemon)

    yield

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)
