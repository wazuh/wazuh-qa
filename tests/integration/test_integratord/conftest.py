'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''


import pytest

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules import integratord as integrator
from wazuh_testing.modules.integratord.event_monitor import check_integratord_event


@pytest.fixture(scope='function')
def wait_for_start_module(request):
    # Wait for integratord thread to start
    file_monitor = FileMonitor(LOG_FILE_PATH)
    check_integratord_event(file_monitor=file_monitor, timeout=20,
                            callback=generate_monitoring_callback(integrator.CB_INTEGRATORD_THREAD_READY),
                            error_message=integrator.ERR_MSG_VIRUST_TOTAL_ENABLED_NOT_FOUND)


@pytest.fixture(scope='module')
def get_integration_api_key():
    return global_parameters.integration_api_key


@pytest.fixture(scope='module')
def replace_configuration_api_key(configuration, get_integration_api_key):
    """
    Replace the API key in the configuration file with the one provided by the environment variable.
    """
    return configuration.replace('API_KEY', get_integration_api_key)
