# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
import wazuh_testing.api as api
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import get_service
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

if sys.platform == 'win32':
    location = r'C:\TESTING\testfile.txt'
    prefix = AGENT_DETECTOR_PREFIX
else:
    location = '/tmp/testing.txt'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

wazuh_component = get_service()

parameters = [
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': '@source'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': 'agent.type'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': 'agent.location'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': 'agent.idgroup'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': 'group.groupnname'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': '109304'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': 'TestingTagNames'},
    {'LOCATION': f'{location}', 'LABEL': 'myapp', 'KEY': '?¿atag_tname'},
]
metadata = [
    {'location': f'{location}', 'label': 'myapp', 'key': '@source'},
    {'location': f'{location}', 'label': 'myapp', 'key': 'agent.type'},
    {'location': f'{location}', 'label': 'myapp', 'key': 'agent.location'},
    {'location': f'{location}', 'label': 'myapp', 'key': 'agent.idgroup'},
    {'location': f'{location}', 'label': 'myapp', 'key': 'group.groupnname'},
    {'location': f'{location}', 'label': 'myapp', 'key': '109304'},
    {'location': f'{location}', 'label': 'myapp', 'key': 'TestingTagNames'},
    {'location': f'{location}', 'label': 'myapp', 'key': '?¿atag_tname'}
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LABEL'], x['KEY']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_label(get_configuration, configure_environment, restart_logcollector):
    """Check if the Wazuh runs correctly with the specified label field value.

    Ensure logcollector allows the specified label attributes. Also, in the case of the manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different than the real configuration.
    """
    cfg = get_configuration['metadata']

    log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)

    if wazuh_component == 'wazuh-manager':
        real_configuration = dict((key, cfg[key]) for key in ['location'])
        real_configuration['label'] = {'key': cfg['key'], 'item': cfg['label']}
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')
