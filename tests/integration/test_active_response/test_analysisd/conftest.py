# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest

from wazuh_testing.tools import configuration
@pytest.fixture(scope='session')
def configure_local_internal_options_analysisd():
    """Fixture to configure the local internal options file."""
    # Define local internal options for analysisd tests
    local_internal_options = {'analysisd.debug': '2', 'monitord.rotate_log': '0'}

    # Backup the old local internal options
    backup_local_internal_options = configuration.get_wazuh_local_internal_options()

    # Set the new local internal options configuration
    configuration.set_wazuh_local_internal_options(configuration.create_local_internal_options(local_internal_options))

    yield

    # Backup the old local internal options cofiguration
    configuration.set_wazuh_local_internal_options(backup_local_internal_options)


@pytest.fixture(scope='function')
def set_wazuh_configuration_analysisd(configuration, set_wazuh_configuration, configure_local_internal_options_analysisd):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
        configure_local_internal_options_analysisd (fixture): Set the local_internal_options.conf file.
    """
    yield
