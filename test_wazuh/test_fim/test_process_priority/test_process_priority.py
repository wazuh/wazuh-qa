# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from copy import deepcopy

import pytest

from wazuh_testing.fim import generate_params
from wazuh_testing.tools import check_apply_test, load_wazuh_configurations, get_process

# All tests in this module apply to linux only
pytestmark = [pytest.mark.linux, pytest.mark.darwin]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True
monitoring_modes = ['scheduled']
test_directories = []

# configurations

priority_list = ['0', '4', '-5']

p, m = generate_params(modes=monitoring_modes)

params, metadata = list(), list()
for pr in priority_list:
    for p_dict, m_dict in zip(p, m):
        p_dict['PROCESS_PRIORITY'] = pr
        m_dict['process_priority'] = pr
        params.append(deepcopy(p_dict))
        metadata.append(deepcopy(m_dict))

configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


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
    assert syscheckd_process.nice() == priority, f'Process {process_name} has not updated its priority.'
