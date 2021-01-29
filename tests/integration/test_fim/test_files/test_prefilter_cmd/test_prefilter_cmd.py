# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess

import distro
import pytest
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

prefilter = '/usr/sbin/prelink -y'
conf_params, conf_metadata = generate_params(extra_params={'PREFILTER_CMD': prefilter})

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=conf_params,
                                           metadata=conf_metadata
                                           )


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='session')
def check_prelink():
    # Call script to install prelink if it is not installed
    path = os.path.dirname(os.path.abspath(__file__))
    dist_list = ['centos', 'fedora', 'rhel']
    dist = 'ubuntu' if distro.id() not in dist_list else 'fedora'
    subprocess.call([f'{path}/data/install_prelink.sh', dist])


# tests


@pytest.mark.parametrize('tags_to_apply', [
    ({'prefilter_cmd'})
])
def test_prefilter_cmd(tags_to_apply, get_configuration, configure_environment, check_prelink, restart_syscheckd,
                       wait_for_fim_start):
    """
    Check if prelink is installed and syscheck works

    This test was implemented when prefilter_cmd could only be set with 'prelink'.

    This test will have to updated if prefilter_cmd is updated as well.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if get_configuration['metadata']['prefilter_cmd'] == '/usr/sbin/prelink -y':
        prelink = get_configuration['metadata']['prefilter_cmd'].split(' ')[0]
        assert os.path.exists(prelink), f'Prelink is not installed'
