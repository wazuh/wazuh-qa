# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import sys

from wazuh_testing.tools import (LOG_FILE_PATH)
from wazuh_testing.tools import (FileMonitor, truncate_file,
                                 restart_wazuh_service,
                                 restart_wazuh_service_windows)


@pytest.fixture(scope='module')
def restart_wazuh(get_configuration, request):
    # Reset ossec.log and start a new monitor
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)

    # Restart Wazuh and wait for the command to end
    if sys.platform == 'win32':
        # Restart Wazuh and wait for the command to end
        # As windows doesn't have daemons everything runs on a single process, so we need to restart everything
        restart_wazuh_service_windows()

    elif sys.platform == 'linux2' or sys.platform == 'linux':
        restart_wazuh_service()
