# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

def callback_detect_start_gcp(line):
    if 'wm_gcp_main(): INFO: Module started.' in line:
        return line
    return None


def callback_detect_start_fetching_logs(line):
    if 'wm_gcp_main(): DEBUG: Starting fetching of logs.' in line:
        return line
    return None


def callback_detect_start_gcp_sleep(line):
    if 'wm_gcp_main(): DEBUG: Sleeping for ' in line:
        return line
    return None


def detect_gcp_start(file_monitor):
    """
    Detect module gcp-pubsub starts after restarting Wazuh.

    Parameters
    ----------
    file_monitor : FileMonitor
        File log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_start_gcp)


def callback_received_messages_number(line):
    match = re.match(r'.*wm_gcp_run\(\): INFO: - INFO - Received and acknowledged (\d+) messages', line)
    if match:
        return match.group(1)
    return None
