# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re

from jsonschema import validate

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def callback_analysisd_message(line):
    match = re.match(r'^agent (\d{3,}) syscheck (\w+) (.+)$', line)
    if match:
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)
        return match.group(1), match.group(2), body
    return None


def callback_fim_event_alert(line):
    try:
        return json.loads(line)
    except json.decoder.JSONDecodeError as e:
        raise e


def callback_fim_error(line):
    match = re.match(r'.* (?:DEBUG|ERROR): ((?:dbsync:|No|Invalid) .*)', line)
    if match:
        return match.group(1)
    return None


def validate_analysis_event(event):
    """Checks if an Analysis event is properly formatted.

    Parameters
    ----------
    event : dict
        Dictionary that represent an event

    """
    with open(os.path.join(_data_path, 'event_analysis_schema.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=event)


def validate_analysis_integrity_state(event):
    """Checks if an Analysis integrity message is properly formatted.

    Parameters
    ----------
    event : dict
        Dictionary that represent an event

    """
    with open(os.path.join(_data_path, 'state_integrity_analysis_schema.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=event)
