# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil

import pytest
from wazuh_testing.api import get_api_details_dict, clean_api_log_files
from wazuh_testing.modules.api import event_monitor as evm
from wazuh_testing.tools import API_LOG_FILE_PATH, API_JSON_LOG_FILE_PATH, WAZUH_API_CONF, WAZUH_SECURITY_CONF
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
    write_api_conf(WAZUH_API_CONF, backup_config if backup_config else {})

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
def clean_log_files():
    """Reset the log files of the API and delete the rotated log files."""
    clean_api_log_files()

    yield

    clean_api_log_files()


@pytest.fixture(scope='module')
def restart_api(get_configuration, request):
    # Stop Wazuh and Wazuh API
    control_service('stop')

    # Reset api.log and start a new monitor
    truncate_file(API_LOG_FILE_PATH)
    file_monitor = FileMonitor(API_LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Start Wazuh API
    #for process_name in ['wazuh-apid', 'wazuh-modulesd', 'wazuh-analysisd', 'wazuh-execd', 'wazuh-db', 'wazuh-remoted']:
    #    control_service('start', daemon=process_name)
    control_service('start')


@pytest.fixture(scope='module')
def wait_for_start(get_configuration, request):
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        get_configuration(fixture): Get configurations from the module.
        request (fixture): Provide information on the executing test function.
    """
    log_format = 'plain'
    try:
        log_format = get_configuration['configuration']['logs']['format']
    except (KeyError, TypeError):
        pass
    file_to_monitor = API_JSON_LOG_FILE_PATH if log_format == 'json' else API_LOG_FILE_PATH

    evm.check_api_start_log(file_to_monitor=file_to_monitor)


@pytest.fixture(scope='module')
def get_api_details():
    return get_api_details_dict


@pytest.fixture(scope='module')
def restart_api_module(request):
    # Stop Wazuh and Wazuh API
    control_service('stop')

    # Reset api.log and start a new monitor
    truncate_file(API_LOG_FILE_PATH)
    file_monitor = FileMonitor(API_LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Start Wazuh API
    control_service('start')


@pytest.fixture(scope='module')
def wait_for_start_module(request):
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    evm.check_api_start_log(file_to_monitor=API_LOG_FILE_PATH)
