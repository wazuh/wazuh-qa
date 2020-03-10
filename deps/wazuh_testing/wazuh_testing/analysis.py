# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from copy import deepcopy
from datetime import datetime

from jsonschema import validate, exceptions

from wazuh_testing import logger

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

with open(os.path.join(_data_path, 'analysis_alert.json'), 'r') as f:
    linux_schema = json.load(f)

with open(os.path.join(_data_path, 'analysis_alert_windows.json'), 'r') as f:
    win32_schema = json.load(f)

with open(os.path.join(_data_path, 'state_integrity_analysis_schema.json'), 'r') as f:
    state_integrity_analysis_schema = json.load(f)

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
        try:
            line = line.decode()
        except UnicodeDecodeError as e:
            print(f'Cannot decode: {line}')
            raise e
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


def get_wazuh_db_message(item, keyword: str = None):
    data, response = item
    match = re.match(r'^agent (\d{3,}) \w+ (\w+) (.+)$', data.decode())
    if match:
        if keyword is not None and keyword not in match.group(2):
            return None
        try:
            body = json.loads(match.group(3))
        except json.decoder.JSONDecodeError:
            body = match.group(3)

        return match.group(1), match.group(2), body


def callback_wazuh_db_message(item):
    if callback_wazuhdb_message_added_and_modified(item) or callback_wazuh_db_message_deleted(item):
        return get_wazuh_db_message(item)


def callback_wazuh_db_integrity(item):
    return get_wazuh_db_message(item, keyword='integrity')


def callback_wazuh_db_scan(item):
    return get_wazuh_db_message(item, keyword='scan')


def callback_fim_alert(line):
    try:
        alert = json.loads(line)
        # Avoid syscheck alerts that are not 'added', 'modified' or 'deleted'
        if alert['rule']['id'] in ['550', '553', '554'] and 'syscheck' in alert:
            return alert
    except json.decoder.JSONDecodeError:
        return None


def callback_fim_error(line):
    match = re.match(r'.* (?:DEBUG|ERROR): ((?:dbsync:|No|Invalid) .*)', line)
    if match:
        return match.group(1)
    return None


def validate_analysis_alert(alert, schema='linux'):
    """Check if an Analysis event is properly formatted.

    Parameters
    ----------
    alert : dict
        Dictionary that represent an alert
    schema : str, optional
        String with the platform to validate the alert from. Default `linux`
    """
    if schema == 'win32':
        _schema = win32_schema
    else:
        _schema = linux_schema
    validate(schema=_schema, instance=alert)


def validate_analysis_alert_complex(alert, event, schema='linux'):
    """Check if an Analysis alert is properly formatted in reference to its Syscheck event.

    Parameters
    ----------
    alert : dict
        Dictionary that represents an alert
    event : dict
        Dictionary that represents an event
    event : dict
        Dictionary that represent an event
    schema : str, optional
        String with the schema to apply. Default `linux`
    """
    def validate_attributes(syscheck_alert, syscheck_event, event_field, suffix):
        for attribute, value in syscheck_event['data'][event_field].items():
            # Skip certain attributes since their alerts will not have them
            if attribute in ['type', 'checksum', 'attributes'] or ('inode' in attribute and schema == 'win32'):
                continue
            # Change `mtime` format to match with alerts
            elif attribute == 'mtime':
                value = datetime.utcfromtimestamp(value).isoformat()
            # Remove `hash_` from hash attributes since alerts do not have them
            elif 'hash' in attribute:
                attribute = attribute.split('_')[-1]
            # `perm` attribute has a different format on Windows
            elif 'perm' in attribute and schema == 'win32':
                attribute = 'win_perm'
                win_perm_list = []
                for win_perm in value.split(','):
                    user, effect, permissions = re.match(r'^(.+?) \((.+?)\): (.+?)$', win_perm).groups()
                    win_perm_list.append({'name': user.strip(' '), effect: permissions.upper().split('|')})
                value = win_perm_list
            attribute = '{}name'.format(attribute[0]) if attribute in ['user_name', 'group_name'] else attribute
            assert str(value) == str(syscheck_alert['{}_{}'.format(attribute, suffix)]), \
                f"{value} not equal to {syscheck_alert['{}_{}'.format(attribute, suffix)]}"
        if 'tags' in event['data']:
            assert event['data']['tags'] == syscheck_alert['tags'][0], f'Tags not in alert or with different value'
        if 'content_changes' in event['data']:
            assert event['data']['content_changes'] == syscheck_alert['diff']
    try:
        validate_analysis_alert(alert, schema)
    except exceptions.ValidationError as e:
        logger.error(f'Validation Error with: {alert}')
        raise e
    try:
        validate_attributes(deepcopy(alert['syscheck']), deepcopy(event), 'attributes', 'after')
        if event['data']['type'] == 'modified':
            validate_attributes(deepcopy(alert['syscheck']), deepcopy(event), 'old_attributes', 'before')
    except KeyError:
        raise KeyError('Alert does not have the same keys as the event.')


def validate_analysis_integrity_state(event):
    """Check if an Analysis integrity message is properly formatted.

    Parameters
    ----------
    event : dict
        Candidate event to be validated against the state integrity schema
    """
    validate(schema=state_integrity_analysis_schema, instance=event)
