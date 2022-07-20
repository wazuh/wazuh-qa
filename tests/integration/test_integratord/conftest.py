# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.tools.services import control_service

@pytest.fixture(scope='function')
def restart_wazuh_function():
    """Restart wazuh-modulesd daemon before starting a test, and stop it after finishing"""
    control_service('restart')
    yield
    control_service('stop')