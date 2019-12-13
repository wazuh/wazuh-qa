# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import psutil

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, generate_params)
from wazuh_testing.tools import (FileMonitor, check_apply_test, load_wazuh_configurations, PREFIX)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
force_restart_after_restoring = True
monitoring_modes = ['realtime']
test_directories = []
priority = 0

# configurations

conf_params, conf_metadata = generate_params({'PROCESS_PRIORITY': str(priority)}, {'process_priority': str(priority)},
                                             modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

@pytest.mark.parametrize('priority, tags_to_apply', [
    (priority, {'ossec_conf'})
])
def test_process_priority(priority, tags_to_apply, get_configuration,
                          configure_environment, restart_syscheckd):
    """ Check if the ossec-syscheckd service priority is updated correctly using
        the <process_priority> tag in ossec.conf.

        After applying the configuration, the process is searched and checked
        if the applied priority is equal to the one it has.
    """

    def get_process(search_name):
        """ Search process by its name """
        for proc in psutil.process_iter():
            if proc.name() == search_name:
                return proc

        return None

    process_name = 'ossec-syscheckd'
    syscheckd_process = get_process(process_name)

    assert syscheckd_process != None, f'Process {process_name} not found'
    assert syscheckd_process.nice() == priority, f'Process {process_name} has not updated its priority.'
