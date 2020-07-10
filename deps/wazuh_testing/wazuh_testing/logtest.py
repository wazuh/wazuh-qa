# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re


# Callbacks

def callback_logtest_started(line):
    match = re.match(r'.*INFO: \(\d+\): Logtest started', line)
    if match:
        return True
    return None


def callback_logtest_disabled(line):
    match = re.match(r'.*INFO: \(\d+\): Logtest disabled', line)
    if match:
        return True
    return None


def callback_configuration_error(line):
    match = re.match(r'.*ERROR: \(\d+\): Invalid value for element', line)
    if match:
        return True
    return None
