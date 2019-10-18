# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing.mitre import (CHECK_ALL, LOG_FILE_PATH, 
                                callback_detect_mitre_event, validate_mitre_event)
from wazuh_testing.tools import (FileMonitor)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
checkers = {CHECK_ALL}

# tests

def test_mitre_alert(configure_local_rules):
    """Checks files are ignored in subdirectory according to configuration"""
    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=60, callback=callback_detect_mitre_event).result()
    validate_mitre_event(event, checkers)
    time.sleep(2)
    

