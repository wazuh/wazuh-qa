# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import shutil

import pytest

from wazuh_testing.tools import control_service
from wazuh_testing.tools import SocketMonitor, SocketController


@pytest.fixture(scope='module')
def configure_local_rules(get_configuration, request):
    """Configure a custom rule in local_rules.xml for testing. Restart Wazuh is needed for applying the configuration."""

    # save current configuration
    shutil.copy('/var/ossec/etc/rules/local_rules.xml', '/var/ossec/etc/rules/local_rules.xml.cpy')

    # configuration for testing
    file_test = str(get_configuration)
    shutil.copy(file_test, '/var/ossec/etc/rules/local_rules.xml')

    # restart wazuh service
    control_service('restart')

    yield

    # restore previous configuration
    shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy', '/var/ossec/etc/rules/local_rules.xml')

    # restart wazuh service
    control_service('restart')
