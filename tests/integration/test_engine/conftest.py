# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.modules import engine


@pytest.fixture(scope='function')
def restart_engine_function():
    """Start the wazuh-engine daemon before running a test, and stop it when finished."""
    control_service('restart', daemon=engine.MODULE_NAME)

    yield

    control_service('stop', daemon=engine.MODULE_NAME)


@pytest.fixture(scope='function')
def truncate_engine_files():
    """Truncate all the log files and json alerts files before and after the test execution."""
    log_files = [engine.ENGINE_ALERTS_PATH, engine.ENGINE_LOG_PATH]

    for log_file in log_files:
        truncate_file(log_file)

    yield

    for log_file in log_files:
        truncate_file(log_file)
