# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing.mitre import (callback_detect_mitre_event,
                                 validate_mitre_event, detect_initial_analysisd)
from wazuh_testing.tools import (FileMonitor, LOG_FILE_PATH)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

configurations = []
path_tests = os.path.join(os.getcwd()+"/"+"data"+"/")
for i in range(1, 14):
    file_test = os.path.join(path_tests +"test" + str(i) + ".xml")
    configurations.append(file_test)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

def test_mitre_check_alert(get_configuration, restart_wazuh, configure_local_rules):
    """Checks Mitre alerts have correct format in accordance with configuration"""

    # Wait until analysisd start
    detect_initial_analysisd(wazuh_log_monitor)

    # Wait until Mitre's event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_mitre_event).result()
    validate_mitre_event(event)
