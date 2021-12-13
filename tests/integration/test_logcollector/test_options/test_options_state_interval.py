# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from time import sleep

import pytest
import wazuh_testing.tools.configuration as conf
from wazuh_testing import logcollector
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import check_daemon_status
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=1)
elapsed_time_modification = 1


# Configuration
state_interval = [-2, 753951, 'dummy', 5, 30, 10, 15]
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
state_interval_update_timeout = 10

# Fixtures
@pytest.fixture(scope="module", params=state_interval)
def get_local_internal_options(request):
    """Get configurations from the module."""
    backup_options_lines = conf.get_wazuh_local_internal_options()
    if sys.platform == 'win32':
        conf.add_wazuh_local_internal_options({'\n windows.debug': '2'})
    else:
        conf.add_wazuh_local_internal_options({'\n logcollector.debug': '2'})
    conf.add_wazuh_local_internal_options({'logcollector.state_interval': request.param})

    yield request.param

    conf.set_wazuh_local_internal_options(backup_options_lines)
    control_service('restart')


def test_options_state_interval(get_local_internal_options, file_monitoring):
    """Check if logcollector is running correctly with the specified logcollector.state_interval option.

    Raises:
        AssertionError: If the elapsed time is different from the interval.
        TimeoutError: If the expected callback is not generated.
    """
    interval = get_local_internal_options
    if not isinstance(interval, int) or (interval not in range(0, 36001)):
        with pytest.raises(ValueError):
            if sys.platform == 'win32':
                pytest.xfail("Windows agent allows invalid localfile configuration:\
                                https://github.com/wazuh/wazuh/issues/10890")
            control_service('restart')
            log_callback = logcollector.callback_invalid_state_interval(interval)
            wazuh_log_monitor.start(timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=log_callback,
                                    error_message=f"The message: 'Invalid definition for "
                                                  f"logcollector.state_interval: {interval}.' didn't appear")
    else:
            control_service('restart')
            sleep(state_interval_update_timeout)
            logcollector.wait_statistics_file(timeout=interval + 5)
            previous_modification_time = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
            last_modification_time = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
            while last_modification_time == previous_modification_time:
                sleep(elapsed_time_modification)
                last_modification_time = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
            elapsed = last_modification_time - previous_modification_time
            if sys.platform == 'win32':
                assert interval - 30 < elapsed < interval + 30
            else:
                assert interval - 1 < elapsed < interval + 1