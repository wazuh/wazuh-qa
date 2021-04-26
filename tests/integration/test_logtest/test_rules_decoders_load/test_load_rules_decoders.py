# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import shutil

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import SocketController

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'load_rules_decoders.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
    tc = list(test_cases)

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))


# Functions used on the test

def create_connection():
    return SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')


def close_connection(connection):
    connection.close()


def create_dummy_session():
    connection = create_connection()
    dummy_request = """{ "version": 1,
            "origin":{"name":"Integration Test","module":"api"},
            "command":"log_processing",
            "parameters":{ "event": "Dummy event to generate new session token","log_format": "syslog",
            "location": "master->/var/log/syslog"}, "origin": {"name":"integration tests", "module": "qa"} }"""

    connection.send(dummy_request, size=True)
    token = json.loads(connection.receive(size=True).rstrip(b'\x00').decode())["data"]["token"]
    close_connection(connection)
    return token


# Tests
@pytest.mark.parametrize('test_case',
                         list(test_cases),
                         ids=[test_case['name'] for test_case in test_cases])
def test_load_rules_decoders(test_case):
    # List to store assert messages
    errors = []

    if 'local_rules' in test_case:
        # save current rules
        shutil.copy('/var/ossec/etc/rules/local_rules.xml',
                    '/var/ossec/etc/rules/local_rules.xml.cpy')

        file_test = test_case['local_rules']
        # copy test rules
        shutil.copy(test_data_path + file_test, '/var/ossec/etc/rules/local_rules.xml')
        shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")

    if 'local_decoders' in test_case:
        # save current decoders
        shutil.copy('/var/ossec/etc/decoders/local_decoder.xml',
                    '/var/ossec/etc/decoders/local_decoder.xml.cpy')

        file_test = test_case['local_decoders']
        # copy test decoder
        shutil.copy(test_data_path + file_test, '/var/ossec/etc/decoders/local_decoder.xml')
        shutil.chown('/var/ossec/etc/decoders/local_decoder.xml', "wazuh", "wazuh")

    # Create session token
    if 'same_session' in test_case and test_case['same_session']:
        session_token = create_dummy_session()

    for stage in test_case['test_case']:

        for i in range(stage['repeat'] if 'repeat' in stage else 1):

            connection = create_connection()
            # Generate logtest request
            if 'same_session' in test_case and test_case['same_session']:
                request_pattern = """{{ "version":1,
                    "origin":{{"name":"Integration Test","module":"api"}},
                    "command":"log_processing",
                    "parameters":{{ "token":"{}" , {} , {} , {} }}
                    }}"""
                input = request_pattern.format(session_token, stage['input_event'],
                                               test_case['input_log_format'],
                                               test_case['input_location'])
            else:
                request_pattern = """{{ "version":1,
                    "origin":{{"name":"Integration Test","module":"api"}},
                    "command":"log_processing",
                    "parameters":{{ {} , {} , {} }}
                    }}"""
                input = request_pattern.format(stage['input_event'],
                                               test_case['input_log_format'],
                                               test_case['input_location'])

            # Send request
            connection.send(input, size=True)

            # Get response
            response = connection.receive(size=True).rstrip(b'\x00').decode()

            # Parse logtest response as JSON
            result = json.loads(response)

            close_connection(connection)

            # Check predecoder
            if ('output_predecoder' in stage and
                    json.loads(stage['output_predecoder']) != result["data"]['output']['predecoder']):
                errors.append(stage['stage'])

            # Check decoder
            if ('output_decoder' in stage and
                    json.loads(stage['output_decoder']) != result["data"]['output']['decoder']):
                errors.append(stage['stage'])

            # Check rule
            if 'output_rule_id' in stage and stage['output_rule_id'] != result["data"]['output']['rule']['id']:
                errors.append(stage['stage'])

            # Check alert
            if 'output_alert' in stage and stage['output_alert'] != result["data"]['alert']:
                errors.append(stage['stage'])

    if 'local_rules' in test_case:
        # restore previous rules
        shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy',
                    '/var/ossec/etc/rules/local_rules.xml')
    shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")

    if 'local_decoders' in test_case:
        # restore previous decoders
        shutil.move('/var/ossec/etc/decoders/local_decoder.xml.cpy',
                    '/var/ossec/etc/decoders/local_decoder.xml')
        shutil.chown('/var/ossec/etc/decoders/local_decoder.xml', "wazuh", "wazuh")

    assert not errors, "Failed stage(s) :{}".format("\n".join(errors))
