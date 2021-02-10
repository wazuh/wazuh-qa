# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from wazuh_testing.fim import change_internal_options


# Callbacks
def callback_state_interval_not_valid(line):
    match = re.match(r'.*Invalid definition for agent.state_interval:', line)
    return True if match is not None else None


def callback_state_interval_not_found(line):
    match = re.match(r".*Definition not found for: 'agent.state_interval'", line)
    return True if match is not None else None


def callback_state_file_not_enabled(line):
    match = re.match(r'.*State file is disabled', line)
    return True if match is not None else None


def callback_state_file_enabled(line):
    match = re.match(r'.*State file updating thread started', line)
    return True if match is not None else None


def callback_state_file_updated(line):
    match = re.match(r'.*Updating state file', line)
    return True if match is not None else None


def callback_ack(line):
    match = re.match(r".*Received message: '#!-agent ack ", line)
    return True if match is not None else None


def callback_keepalive(line):
    match = re.match(r'.*Sending keep alive', line)
    return True if match is not None else None


def callback_connected_to_server(line):
    match = re.match(r'.*Connected to the server', line)
    return True if match is not None else None


def set_state_interval(interval, internal_file_path):
    """Set agent.state_interval value on internal_options.conf
    Args:
        interval:
            - Different than `None`: set agent.state_interval
                                     value on internal_options.conf
            - `None`: agent.state_interval will be removed
                      from internal_options.conf
    """
    if interval is not None:
        change_internal_options('agent.state_interval', interval, opt_path=internal_file_path)
    else:
        new_content = ''
        with open(internal_file_path) as opts:
            for line in opts:
                new_line = line if 'agent.state_interval' not in line else ''
                new_content += new_line

        with open(internal_file_path, 'w') as opts:
            opts.write(new_content)