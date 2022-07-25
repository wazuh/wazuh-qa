'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''


import pytest

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor, callback_generator
from wazuh_testing.modules import integratord as integrator


# Fixtures

@pytest.fixture(scope='function')
def wait_for_start_module(request):
    # Wait for Virustotal Integration to start
    file_monitor = FileMonitor(LOG_FILE_PATH)
    file_monitor.start(timeout=20, callback=callback_generator(integrator.CB_INTEGRATORD_THREAD_READY),
                       error_message=integrator.ERR_MSG_VIRUST_TOTAL_ENABLED_NOT_FOUND)
