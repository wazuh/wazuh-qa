# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, generate_params, KEY_WOW64_64KEY, KEY_WOW64_32KEY
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# Variables
key = "HKEY_LOCAL_MACHINE"
sub_key = "SOFTWARE\\test_key"
sub_key_2 = "SOFTWARE\\Classes\\test_key"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_regs = [os.path.join(key, sub_key), os.path.join(key, sub_key_2)]
reg1, reg2 = test_regs
# Configurations
tags = ['tag1', 'tág', '0tag', '000', 'a' * 1000]
conf_params = {'WINDOWS_REGISTRY_1': reg1, 'WINDOWS_REGISTRY_2': reg2}

configurations_path = os.path.join(test_data_path, 'wazuh_registry_tag_conf.yaml')
p, m = generate_params(extra_params=conf_params,
                       apply_to_all=({'FIM_TAGS': tag} for tag in tags),
                       modes=['scheduled'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('key, subkey, arch', [
    (key, sub_key, KEY_WOW64_32KEY),
    (key, sub_key, KEY_WOW64_64KEY),
    (key, sub_key_2, KEY_WOW64_64KEY)
])
def test_tags(key, subkey, arch,
              get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check the tags functionality by applying some tags an ensuring the events raised for the monitored directory has
    the expected tags.

    Parameters
    ----------
    folder : str
        Directory where the file is being created.
    name : str
        Name of the file to be created.
    content : str, bytes
        Content to fill the new file.
    """
    defined_tags = get_configuration['metadata']['fim_tags']

    def tag_validator(event):
        assert defined_tags == event['data']['tags'], f'defined_tags are not equal'

    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch,
                       time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                       min_timeout=global_parameters.default_timeout,
                       triggers_event=True,
                       validators_after_cud=[tag_validator]
                       )
