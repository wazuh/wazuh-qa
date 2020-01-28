# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.fim import generate_params
from wazuh_testing.tools.services import get_process
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True
monitoring_modes = ['scheduled']
test_directories = []

# configurations

priority_list = ['0', '4', '-5']

p, m = generate_params(apply_to_all=({'PROCESS_PRIORITY': priority_value} for priority_value in priority_list), modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def test_process_priority(get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """Check if the ossec-syscheckd service priority is updated correctly using
       <process_priority> tag in ossec.conf.
    """
    check_apply_test({'ossec_conf'}, get_configuration['tags'])

    priority = int(get_configuration['metadata']['process_priority'])
    process_name = 'ossec-syscheckd'
    syscheckd_process = get_process(process_name)

    assert syscheckd_process is not None, f'Process {process_name} not found'
    print("nice: " + str(syscheckd_process.nice()) + ", priority: " + str(priority))
    assert syscheckd_process.nice() == priority, f'Process {process_name} has not updated its priority.'
