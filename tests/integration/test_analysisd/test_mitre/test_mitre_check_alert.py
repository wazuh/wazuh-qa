# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.mitre import (callback_detect_mitre_event, validate_mitre_event)
from wazuh_testing.tools import ALERT_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# variables

wazuh_alert_monitor = FileMonitor(ALERT_FILE_PATH)
_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

configurations = []
for i in range(1, 15):
    file_test = os.path.join(_data_path, f"test{i}.xml")
    configurations.append(file_test)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def test_mitre_check_alert(get_configuration, configure_local_rules, restart_wazuh_alerts):
    """Check Mitre alerts have correct format in accordance with configuration"""

    # Wait until Mitre's event is detected
    if get_configuration != os.path.join(_data_path, f"test8.xml"):
        event = wazuh_alert_monitor.start(timeout=30, callback=callback_detect_mitre_event).result()
        validate_mitre_event(event)
