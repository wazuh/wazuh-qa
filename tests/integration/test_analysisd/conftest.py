# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import shutil

import pytest

from wazuh_testing.tools import WAZUH_LOGS_PATH, LOG_FILE_PATH
from wazuh_testing.tools.monitoring import QueueMonitor, ManInTheMiddle, FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status


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
def wait_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""
    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)


@pytest.fixture(scope='module')
def configure_mitm_environment_analysisd(request):
    """Use MITM to replace analysisd and wazuh-db sockets."""
    def remove_logs():
        for root, dirs, files in os.walk(WAZUH_LOGS_PATH):
            for file in files:
                os.remove(os.path.join(root, file))

    analysis_path = getattr(request.module, 'analysis_path')
    wdb_path = getattr(request.module, 'wdb_path')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running=False)
    remove_logs()

    control_service('start', daemon='wazuh-db', debug_mode=True)
    check_daemon_status(running=True, daemon='wazuh-db')

    mitm_wdb = ManInTheMiddle(socket_path=wdb_path)
    wdb_queue = mitm_wdb.queue
    mitm_wdb.start()

    control_service('start', daemon='ossec-analysisd', debug_mode=True)
    check_daemon_status(running=True, daemon='ossec-analysisd')

    mitm_analysisd = ManInTheMiddle(socket_path=analysis_path, mode='UDP')
    analysisd_queue = mitm_analysisd.queue
    mitm_analysisd.start()

    analysis_monitor = QueueMonitor(queue_item=analysisd_queue)
    wdb_monitor = QueueMonitor(queue_item=wdb_queue)

    setattr(request.module, 'analysis_monitor', analysis_monitor)
    setattr(request.module, 'wdb_monitor', wdb_monitor)

    yield

    mitm_analysisd.shutdown()
    mitm_wdb.shutdown()

    for daemon in ['wazuh-db', 'ossec-analysisd']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running=False, daemon=daemon)

    control_service('start')
