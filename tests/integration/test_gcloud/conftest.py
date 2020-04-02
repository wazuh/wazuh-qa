# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.gcloud import detect_gcp_start
from wazuh_testing.tools.configuration import get_wazuh_conf, write_wazuh_conf, set_section_wazuh_conf
from wazuh_testing.tools.services import control_service


@pytest.fixture(scope='module')
def wait_for_gcp_start(get_configuration, request):
    # Wait for module gpc-pubsub starts
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    detect_gcp_start(file_monitor)


@pytest.fixture(scope='module')
def configure_environment(get_configuration, request):
    """Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration."""

    # save current configuration
    backup_config = get_wazuh_conf()

    # configuration for testing
    elements = get_configuration.get('elements')
    test_config = set_section_wazuh_conf(get_configuration.get('section'),
                                         new_elements=elements)

    # set new configuration
    write_wazuh_conf(test_config)

    # Call extra functions before yield
    if hasattr(request.module, 'extra_configuration_before_yield'):
        func = getattr(request.module, 'extra_configuration_before_yield')
        func()

    # Set current configuration
    global_parameters.current_configuration = get_configuration

    yield

    # restore previous configuration
    write_wazuh_conf(backup_config)

    # Call extra functions after yield
    if hasattr(request.module, 'extra_configuration_after_yield'):
        func = getattr(request.module, 'extra_configuration_after_yield')
        func()

    if hasattr(request.module, 'force_restart_after_restoring'):
        if getattr(request.module, 'force_restart_after_restoring'):
            control_service('restart')
