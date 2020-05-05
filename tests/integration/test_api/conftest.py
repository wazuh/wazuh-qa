# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import shutil
import sys
from base64 import b64encode
import subprocess

import pytest
import requests
import yaml

from wazuh_testing.fim import callback_detect_api_start
from wazuh_testing.tools.configuration import get_api_conf, write_api_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

if sys.platform == 'linux':
    from wazuh_testing.tools import API_LOG_FILE_PATH, WAZUH_PATH, WAZUH_API_CONF


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


with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'common.yaml'), 'r') as stream:
    common = yaml.safe_load(stream)['variables']


def get_base_url(protocol, host, port, version):
    return f"{protocol}://{host}:{port}/{version}"


def get_login_headers(user, password):
    basic_auth = f"{user}:{password}".encode()
    return {'Content-Type': 'application/json',
                     'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_token_login_api(protocol, host, port, version, user, password, timeout):
    login_url = f"{get_base_url(protocol, host, port, version)}{common['login_endpoint']}"
    response = requests.get(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

    if response.status_code == 200:
        return json.loads(response.content.decode())['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")


@pytest.fixture(scope='module')
def get_api_details():
    def _get_api_details(protocol=common['protocol'], host=common['host'], port=common['port'],
                         version=common['version'], user=common['user'], password=common['pass'], timeout=10):
        return {
            'base_url': get_base_url(protocol, host, port, version),
            'auth_headers': {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {get_token_login_api(protocol, host, port, version, user, password, timeout)}'
            }
        }
    return _get_api_details

