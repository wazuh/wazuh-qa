# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def callback_detect_enabled_err(line):
    if 'wm_github_read(): ERROR: Invalid content for tag \'enabled\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_only_future_events_err(line):
    if 'wm_github_read(): ERROR: Invalid content for tag \'only_future_events\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_interval_err(line):
    if 'wm_github_read(): ERROR: Invalid content for tag \'interval\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_curl_max_size_err(line):
    if 'wm_github_read(): ERROR: Invalid content for tag \'curl_max_size\' at module \'github\'. '\
       'The minimum value allowed is 1KB.' in line:
        return line
    return None


def callback_detect_time_delay_err(line):
    if 'wm_github_read(): ERROR: Invalid content for tag \'time_delay\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_org_name_err(line):
    if 'wm_github_read(): ERROR: Empty content for tag \'org_name\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_api_token_err(line):
    if 'wm_github_read(): ERROR: Empty content for tag \'api_token\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_event_type_err(line):
    if 'wm_github_read(): ERROR: Invalid content for tag \'event_type\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_read_err(line):
    if 'wm_github_read(): ERROR: Empty content for tag \'api_auth\' at module \'github\'.' in line:
        return line
    return None


def callback_detect_start_github(line):
    if 'wm_github_main(): INFO: Module GitHub started.' in line:
        return line
    return None


def detect_github_start(file_monitor):
    """Detect module github starts after restarting Wazuh.

    Args:
        file_monitor (FileMonitor): File log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_start_github)
