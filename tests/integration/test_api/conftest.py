# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess

import pytest

from wazuh_testing.api import callback_detect_api_start, get_base_url, get_token_login_api, API_HOST, \
    API_LOGIN_ENDPOINT, API_PASS, API_PORT, API_USER, API_PROTOCOL, API_VERSION
from wazuh_testing.tools import API_LOG_FILE_PATH, WAZUH_PATH, WAZUH_API_CONF
from wazuh_testing.tools.configuration import get_api_conf, write_api_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor


@pytest.fixture(scope='module')
def configure_api_environment(get_configuration, request):
    """Configure a custom environment for API testing. Restart API is needed for applying the configuration."""

    # Save current configuration
    backup_config = get_api_conf(WAZUH_API_CONF)

    # Set new configuration
    write_api_conf(WAZUH_API_CONF, get_configuration.get('configuration'))

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
    write_api_conf(WAZUH_API_CONF, backup_config)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            subprocess.call([os.path.join(WAZUH_PATH, 'bin', 'wazuh-apid'), 'restart'])


@pytest.fixture(scope='module')
def restart_api(get_configuration, request):
    # Reset api.log and start a new monitor
    subprocess.call([os.path.join(WAZUH_PATH, 'bin', 'wazuh-apid'), 'stop'])
    truncate_file(API_LOG_FILE_PATH)
    file_monitor = FileMonitor(API_LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    subprocess.call([os.path.join(WAZUH_PATH, 'bin', 'wazuh-apid'), 'start'])


@pytest.fixture(scope='module')
def wait_for_start(get_configuration, request):
    # Wait for API to start
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    file_monitor.start(timeout=20, callback=callback_detect_api_start,
                       error_message='Did not receive expected "INFO: Listening on ..." event')


@pytest.fixture(scope='module')
def get_api_details():
    def _get_api_details(protocol=API_PROTOCOL, host=API_HOST, port=API_PORT, version=API_VERSION, user=API_USER, password=API_PASS,
                         login_endpoint=API_LOGIN_ENDPOINT, timeout=10):
        return {
            'base_url': get_base_url(protocol, host, port, version),
            'auth_headers': {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {get_token_login_api(protocol, host, port, version, user, password, login_endpoint, timeout)}'
            }
        }
    return _get_api_details
