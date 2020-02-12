# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from copy import deepcopy
from datetime import datetime

from jsonschema import validate

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def callback_analysisd_message(line):
    if isinstance(line, bytes):
        line = line.decode()
    match = re.match(r'^agent (\d{3,}) syscheck (\w+) (.+)$', line)
    if match:
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)
        return match.group(1), match.group(2), body
    return None


def callback_analysisd_event(line):
    if isinstance(line, bytes):
        line = line.decode()
    match = re.match(r'.+syscheck\:(.+)', line)
    if match:
        try:
            body = json.loads(match.group(1))
            if body.get('type', None) == 'event':
                return line, body
        except json.decoder.JSONDecodeError:
            return None


def callback_analysisd_agent_id(line):
    if isinstance(line, bytes):
        line = line.decode()
    match = re.match(r'[^\[\]]+\[(\d+?)\].+\w+:.+$', line)
    if match:
        return match.group(1)


def callback_wazuhdb_message_added_and_modified(item):
    data, response = item
    match = re.match(r'^agent (\d{3,}) \w+ (save2) (.+)$', data.decode())
    if match:
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)
        return match.group(1), match.group(2), body


def callback_wazuh_db_message_deleted(item):
    data, response = item
    match = re.match(r'^agent (\d{3,}) \w+ (delete) (.+)$', data.decode())
    if match:
        return match.group(1), match.group(2), match.group(3)


def callback_wazuh_db_message(item):
    if callback_wazuhdb_message_added_and_modified(item) or callback_wazuh_db_message_deleted(item):
        data, response = item
        match = re.match(r'^agent (\d{3,}) \w+ (\w+) (.+)$', data.decode())
        if match:
            try:
                body = json.loads(match.group(3))
            except json.decoder.JSONDecodeError:
                body = match.group(3)
            return match.group(1), match.group(2), body


def callback_fim_alert(line):
    try:
        return json.loads(line)
    except json.decoder.JSONDecodeError as e:
        raise e


def callback_fim_error(line):
    match = re.match(r'.* (?:DEBUG|ERROR): ((?:dbsync:|No|Invalid) .*)', line)
    if match:
        return match.group(1)
    return None


def validate_analysis_alert(alert):
    """Checks if an Analysis event is properly formatted.

    Parameters
    ----------
    alert : dict
        Dictionary that represent an alert

    """
    with open(os.path.join(_data_path, 'event_analysis_schema.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=alert)


def validate_analysis_alert_complex(alert, event):
    """Check if an Analysis alert is properly formatted in reference to its Syscheck event.

    Parameters
    ----------
    alert : dict
        Dictionary that represents an alert
    event : dict
        Dictionary that represents an event
    """
    def validate_attributes(syscheck_alert, syscheck_event, event_field, suffix):
        for attribute, value in syscheck_event['data'][event_field].items():
            if attribute in ['type', 'checksum']:
                continue
            else:
                if attribute == 'mtime':
                    value = datetime.utcfromtimestamp(value).isoformat()
                elif 'hash' in attribute:
                    attribute = attribute.split('_')[-1]
                attribute = '{}name'.format(attribute[0]) if attribute in ['user_name', 'group_name'] else attribute
                assert str(value) == str(syscheck_alert['{}_{}'.format(attribute, suffix)]), \
                    f"{value} not equal to {syscheck_alert['{}_{}'.format(attribute, suffix)]}"
        if 'tags' in event['data']:
            assert event['data']['tags'] == syscheck_alert['tags'][0], f'Tags not in alert or with different value'
        if 'content_changes' in event['data']:
            assert event['data']['content_changes'] == syscheck_alert['diff']

    # Move this out of this scope
    with open(os.path.join(_data_path, 'event_analysis_schema.json'), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=alert)

    validate_attributes(deepcopy(alert['syscheck']), deepcopy(event), 'attributes', 'after')
    if event['data']['type'] == 'modified':
        validate_attributes(deepcopy(alert['syscheck']), deepcopy(event), 'old_attributes', 'before')


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
