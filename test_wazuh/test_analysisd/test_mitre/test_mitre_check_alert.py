# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing.mitre import (CHECK_ALL, LOG_FILE_PATH, callback_detect_mitre_event,
                                 validate_mitre_event)
from wazuh_testing.tools import (FileMonitor)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
checkers = {CHECK_ALL}

configurations = []
path_tests = os.path.join(os.getcwd()+"/"+"data"+"/")
for i in range(1,9):
    file_test = os.path.join(path_tests +"test" + str(i) + ".xml")
    configurations.append(file_test)

# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

# tests

def test_mitre_check_alert(get_configuration, configure_local_rules):
    """Checks Mitre alerts have correct format in accordance with configuration"""

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=20, callback=callback_detect_mitre_event).result()
    validate_mitre_event(event, checkers)
