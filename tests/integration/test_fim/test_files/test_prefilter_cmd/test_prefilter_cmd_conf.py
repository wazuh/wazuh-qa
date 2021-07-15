# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess

import distro
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, check_fim_start, callback_configuration_error
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1), pytest.mark.agent, pytest.mark.server]

#Variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_prefilter_cmd_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

#Configurations
prefilter = '/usr/sbin/prelink -y'

conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str, 'PREFILTER_CMD': prefilter})

configuration_ids = []

for params in conf_params:
    fim_modes =  params['FIM_MODE'].keys()
    for fim_mode in fim_modes:
        configuration_ids.append(f"prefilter_cmd_conf_{fim_mode}")

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


#Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='session')
def install_prelink():
    # Call script to install prelink if it is not installed
    path = os.path.dirname(os.path.abspath(__file__))
    dist_list = ['centos', 'fedora', 'rhel']
    dist = 'ubuntu' if distro.id() not in dist_list else 'fedora'
    subprocess.call([f'{path}/data/install_prelink.sh', dist])


#Tests
def test_prefilter_cmd_conf(get_configuration, configure_environment, install_prelink, restart_syscheckd):
    """Check if prelink is installed and syscheck works. If prelink is not installed, checks if an error log is received.

    This test was implemented when prefilter_cmd could only be set with 'prelink'.

    This test will have to updated if prefilter_cmd is updated as well.
    """
    if os.path.exists(prefilter.split(' ')[0]):
        check_fim_start(wazuh_log_monitor)
    else:
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_configuration_error,
                                    error_message=f"The expected 'Configuration error at etc/ossec.conf' "
                                                  f"message has not been produced")
