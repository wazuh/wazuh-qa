'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest

from wazuh_testing import T_5
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules import analysisd
from wazuh_testing.modules.analysisd.event_monitor import check_analysisd_event
from wazuh_testing.modules.integratord import event_monitor as evm


@pytest.fixture(scope='function')
def wait_for_start_module(request):
    # Wait for integratord thread to start
    file_monitor = FileMonitor(LOG_FILE_PATH)
    evm.check_integratord_thread_ready(file_monitor=file_monitor)

    # Wait for analysisd to start successfully (to detect changes in the alerts.json file)
    check_analysisd_event(file_monitor=file_monitor, timeout=T_5,
                          callback=analysisd.CB_ANALYSISD_STARTUP_COMPLETED,
                          error_message=analysisd.ERR_MSG_STARTUP_COMPLETED_NOT_FOUND)
