# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import distro
import os
import subprocess

import pytest

from wazuh_testing.fim import LOG_FILE_PATH, detect_initial_scan, generate_params
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations, restart_wazuh_daemon, truncate_file)

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1')]
force_restart_after_restoring = True

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

prefilter = '/usr/sbin/prelink -y'
conf_params, conf_metadata = generate_params(extra_params={'PREFILTER_CMD': prefilter},
                                             extra_metadata={'prefilter_cmd': prefilter})

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
    if distro.id() in dist_list:
        dist = 'rpm -qa'
        installer = 'yum -y install'
    else:
        dist = 'dpkg -l'
        installer = 'apt-get install'
    subprocess.call([f'{path}/data/install_prelink.sh', dist, installer])

# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'prefilter_cmd'})
])
def test_prefilter_cmd(tags_to_apply, get_configuration, configure_environment, check_prelink):
    """Checks if prelink is installed and syscheck works."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if get_configuration['metadata']['prefilter_cmd'] == '/usr/sbin/prelink -y':
        prelink = get_configuration['metadata']['prefilter_cmd'].split(' ')[0]
        # assert os.path.exists(prelink), f'Prelink is not installed'
        truncate_file(LOG_FILE_PATH)
        restart_wazuh_daemon('ossec-syscheckd')
        detect_initial_scan(wazuh_log_monitor)
