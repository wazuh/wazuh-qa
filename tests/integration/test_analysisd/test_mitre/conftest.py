# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.tools import ALERT_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import truncate_file


@pytest.fixture(scope='module')
def restart_wazuh(get_configuration, request):
    # Stop Wazuh
    control_service('stop')

    # Reset ossec.log and start a new monitor
    truncate_file(ALERT_FILE_PATH)
    file_monitor = FileMonitor(ALERT_FILE_PATH)
    setattr(request.module, 'wazuh_alert_monitor', file_monitor)

    # Start Wazuh
    control_service('start')
