# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def callback_detect_enabled_err(line):
    if 'wm_office365_read(): ERROR: Invalid content for tag \'enabled\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_only_future_events_err(line):
    if 'wm_office365_read(): ERROR: Invalid content for tag \'only_future_events\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_interval_err(line):
    if 'wm_office365_read(): ERROR: Invalid content for tag \'interval\' at module \'office365\'. '\
       'The maximum value allowed is 1 day.' in line:
        return line
    return None


def callback_detect_curl_max_size_err(line):
    if 'wm_office365_read(): ERROR: Invalid content for tag \'curl_max_size\' at module \'office365\'. '\
       'The minimum value allowed is 1KB.' in line:
        return line
    return None


def callback_detect_tenant_id_err(line):
    if 'wm_office365_read(): ERROR: Empty content for tag \'tenant_id\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_client_id_err(line):
    if 'wm_office365_read(): ERROR: Empty content for tag \'client_id\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_client_secret_err(line):
    if 'wm_office365_read(): ERROR: Empty content for tag \'client_secret\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_api_type_err(line):
    if 'wm_office365_read(): ERROR: Empty content for tag \'api_type\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_subscription_err(line):
    if 'wm_office365_read(): ERROR: Empty content for tag \'subscription\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_read_err(line):
    if 'wm_office365_read(): ERROR: Empty content for tag \'api_auth\' at module \'office365\'.' in line:
        return line
    return None


def callback_detect_start_office365(line):
    if 'wm_office365_main(): INFO: Module Office365 started.' in line:
        return line
    return None


def detect_office365_start(file_monitor):
    """Detect module office365 starts after restarting Wazuh.

    Args:
        file_monitor (FileMonitor): File log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_start_office365)
