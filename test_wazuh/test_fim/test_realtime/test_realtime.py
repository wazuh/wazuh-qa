# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import time
from datetime import timedelta

import pytest

from wazuh_testing.fim import ALERTS_FILE_PATH, is_fim_scan_ended, load_fim_alerts
from wazuh_testing.tools import truncate_file, wait_for_condition

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2')]
testdir1, testdir2 = test_directories


@pytest.mark.parametrize('folder, filename, mode, content', [
    (testdir1, 'testfile', 'w', "Sample content"),
    (testdir1, 'btestfile', 'wb', b"Sample content"),
    (testdir2, 'testfile', 'w', ""),
    (testdir2, "btestfile", "wb", b"")
])
def _test_regular_file(folder, filename, mode, content, configure_environment, restart_wazuh):
    """Checks if a regular file creation is detected by syscheck"""

    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Wait for FIM scan to finish
    wait_for_condition(lambda: is_fim_scan_ended() > -1, timeout=60)
    time.sleep(11)
    # Wait until alerts are generated
    wait_for_condition(lambda: len(load_fim_alerts(n_last=1)) == 1, timeout=5)

    truncate_file(ALERTS_FILE_PATH)
