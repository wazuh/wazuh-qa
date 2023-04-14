# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil

import pytest

import wazuh_testing as fw
from wazuh_testing import api
from wazuh_testing.modules.api import event_monitor as evm
from wazuh_testing.tools import configuration as conf
from wazuh_testing.tools import services as svcs
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor


@pytest.fixture(scope='module')
def configure_api_environment(get_configuration, request):
    """Configure a custom environment for API testing. Restart API is needed for applying the configuration."""

    # Save current configuration
    backup_config = conf.get_api_conf(fw.WAZUH_API_CONF)

    # Save current security config
    backup_security_config = conf.get_api_conf(fw.WAZUH_SECURITY_CONF) if \
        os.path.exists(fw.WAZUH_SECURITY_CONF) else None

    # Set new configuration
    api_config = get_configuration.get('configuration', None)
    if api_config:
        conf.write_api_conf(fw.WAZUH_API_CONF, api_config)

    # Set security configuration
    security_config = get_configuration.get('security_config', None)
    if security_config:
        conf.write_security_conf(fw.WAZUH_SECURITY_CONF, security_config)

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
    conf.write_api_conf(fw.WAZUH_API_CONF, backup_config if backup_config else {})

    # Restore previous RBAC configuration
    if backup_security_config:
        conf.write_security_conf(fw.WAZUH_SECURITY_CONF, backup_security_config)
    elif security_config and not backup_security_config:
        os.remove(fw.WAZUH_SECURITY_CONF)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            svcs.control_service('restart')


@pytest.fixture(scope='module')
def clean_log_files():
    """Reset the log files of the API and delete the rotated log files."""
    api.clean_api_log_files()

    yield

    api.clean_api_log_files()


@pytest.fixture(scope='module')
def restart_api(get_configuration, request):
    # Stop Wazuh and Wazuh API
    svcs.control_service('stop')

    # Reset api.log and start a new monitor
    truncate_file(fw.API_LOG_FILE_PATH)
    file_monitor = FileMonitor(fw.API_LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Start Wazuh API
    svcs.control_service('start')


@pytest.fixture(scope='module')
def wait_for_start(get_configuration, request):
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        get_configuration(fixture): Get configurations from the module.
        request (fixture): Provide information on the executing test function.
    """
    evm.check_api_start_log()


@pytest.fixture(scope='function')
def wait_for_start_function(configuration):
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        configuration (dict): Configuration template data.
    """
    log_format = 'plain'
    try:
        log_format = configuration['configuration']['logs']['format']
    except (KeyError, TypeError):
        pass
    file_to_monitor = fw.API_JSON_LOG_FILE_PATH if log_format == 'json' else fw.API_LOG_FILE_PATH

    evm.check_api_start_log(file_to_monitor=file_to_monitor)


@pytest.fixture(scope='module')
def get_api_details():
    return api.get_api_details_dict


@pytest.fixture(scope='module')
def restart_api_module(request):
    # Stop Wazuh and Wazuh API
    svcs.control_service('stop')

    # Reset api.log and start a new monitor
    truncate_file(fw.API_LOG_FILE_PATH)
    file_monitor = FileMonitor(fw.API_LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Start Wazuh API
    svcs.control_service('start')
    evm.check_api_start_log(file_monitor)


@pytest.fixture(scope='module')
def wait_for_start_module(request):
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    evm.check_api_start_log()


@pytest.fixture(scope='function')
def set_api_configuration(configuration):
    """Set API custom configuration.

    Args:
        configuration (dict): Configuration template data to write in the api.yaml.
    """
    # Save current configuration
    backup_config = conf.get_api_conf(fw.WAZUH_API_CONF)

    # Get configuration for testing
    test_config = configuration['configuration']

    # Set the new configuration
    conf.write_api_conf(fw.WAZUH_API_CONF, test_config)

    yield

    # Restore previous configuration
    conf.write_api_conf(fw.WAZUH_API_CONF, backup_config if backup_config else {})


@pytest.fixture(scope='function')
def restart_api_function():
    """Restart all deamons related to the API before the test and stop them after it finished."""
    daemons = fw.API_DAEMONS_REQUIREMENTS

    for daemon in daemons:
        svcs.control_service('restart', daemon=daemon)

    yield

    # Stop daemons in reverse to simulate Wazuh's behavior
    for daemon in daemons[::-1]:
        svcs.control_service('stop', daemon=daemon)
