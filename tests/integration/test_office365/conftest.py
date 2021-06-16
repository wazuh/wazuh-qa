# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.office365 import detect_office365_start


@pytest.fixture(scope='module')
def wait_for_office365_start(get_configuration, request):
    # Wait for module office365 starts
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    detect_office365_start(file_monitor)
