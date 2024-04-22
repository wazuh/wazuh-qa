# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Common unit test fixtures."""
from unittest.mock import patch
import pytest


@pytest.fixture
def logger_mock(request):
    """Fixture to mock common logger methods."""
    logger_to_patch = request.param.get('logger_to_patch', "modules.testing.utils.logger")
    with patch(logger_to_patch) as l_mock:
        patch.object(l_mock, 'warning')
        patch.object(l_mock, 'info')
        patch.object(l_mock, 'debug')
        patch.object(l_mock, 'error')
        yield l_mock