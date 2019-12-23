# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re

from jsonschema import validate

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def callback_fim_event_message(line):
    match = re.match(r'^agent (\d{3,}) syscheck (\w+) (.+)$', line)
    if match:
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)
        return match.group(1), match.group(2), body
    return None


def callback_fim_event_alert(line):
    match = re.match(r'(.+)$', line)
    if match:
        try:
            return json.loads(match.group(1))
        except json.decoder.JSONDecodeError as e:
            raise e
    return None


def validate_analysis_event(event):
    """Checks if a Analysis event is properly formatted.

    Parameters
    ----------
    event : dict
        Dictionary that represent an event

    """
    with open(os.path.join(_data_path, 'alert_schema.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=event)
