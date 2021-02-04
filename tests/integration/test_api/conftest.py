# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil

import pytest
from wazuh_testing.api import callback_detect_api_start, get_api_details_dict
from wazuh_testing.tools import API_LOG_FILE_PATH, WAZUH_API_CONF, WAZUH_SECURITY_CONF
from wazuh_testing.tools.configuration import get_api_conf, write_api_conf, write_security_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service


@pytest.fixture(scope='module')
def configure_api_environment(get_configuration, request):
    """Configure a custom environment for API testing. Restart API is needed for applying the configuration."""

    # Save current configuration
    backup_config = get_api_conf(WAZUH_API_CONF)

    # Save current security config
    backup_security_config = get_api_conf(WAZUH_SECURITY_CONF) if os.path.exists(WAZUH_SECURITY_CONF) else None

    # Set new configuration
    api_config = get_configuration.get('configuration', None)
    if api_config:
        write_api_conf(WAZUH_API_CONF, api_config)

    # Set security configuration
    security_config = get_configuration.get('security_config', None)
    if security_config:
        write_security_conf(WAZUH_SECURITY_CONF, security_config)

    # Create test directories
    if hasattr(request.module, 'test_directories'):
        test_directories = getattr(request.module, 'test_directories')
        for test_dir in test_directories:
            oldmask = os.umask(0000)
            os.makedirs(test_dir, exist_ok=True, mode=0O777)
            os.umask(oldmask)

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    yield

    # Remove created folders (parents)
    if hasattr(request.module, 'test_directories'):
        for test_dir in test_directories:
            shutil.rmtree(test_dir, ignore_errors=True)

    # Restore previous configuration
    if backup_config:
        write_api_conf(WAZUH_API_CONF, backup_config)

    # Restore previous RBAC configuration
    if backup_security_config:
        write_security_conf(WAZUH_SECURITY_CONF, backup_security_config)
    elif security_config and not backup_security_config:
        os.remove(WAZUH_SECURITY_CONF)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            control_service('restart')


@pytest.fixture(scope='module')
def restart_api(get_configuration, request):
    # Stop Wazuh and Wazuh API
    control_service('stop')

    # Reset api.log and start a new monitor
    truncate_file(API_LOG_FILE_PATH)
    file_monitor = FileMonitor(API_LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Start Wazuh and Wazuh API
    control_service('start')


@pytest.fixture(scope='module')
def wait_for_start(get_configuration, request):
    # Wait for API to start
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    file_monitor.start(timeout=20, callback=callback_detect_api_start,
                       error_message='Did not receive expected "INFO: Listening on ..." event')


@pytest.fixture(scope='module')
def get_api_details():
    return get_api_details_dict
