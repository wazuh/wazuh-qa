# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
import shutil
import sys
import time

import pytest
import yaml

from wazuh_testing.analysis import callback_analysisd_message, callback_fim_event_alert, validate_analysis_alert
from wazuh_testing.fim import detect_initial_scan, create_file, REGULAR, modify_file, \
    delete_file, callback_detect_event
from wazuh_testing.tools import WAZUH_PATH, WAZUH_CONF, PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import generate_syscheck_config
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=2)]

# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'syscheck_events.yaml')
with open(messages_path) as f:
    messages = yaml.safe_load(f)
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue'))
monitored_sockets, receiver_sockets = None, None  # These variables will be set in the fixture create_unix_sockets
monitored_sockets_params = [(wdb_path, 'TCP')]
receiver_sockets_params = [(analysis_path, 'UDP')]
used_daemons = ['ossec-analysisd']

# Syscheck variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
n_directories = 0
directories_list = list()
testdir = 'testdir'


# fixtures

@pytest.fixture(scope='module')
def set_syscheck_config():
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('172.20.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    original_conf = open(WAZUH_CONF, 'r').readlines()
    directory = 0

    with open(WAZUH_CONF, 'w') as new_conf:
        syscheck_flag = False
        for line in original_conf:
            if re.match(r'.*\<syscheck\>.*', line):
                new_conf.write('<syscheck>\n')
                syscheck_flag = True
                for attributes in generate_syscheck_config():
                    t_dir = f'{testdir}{directory}'
                    new_conf.write(
                        f'<directories realtime="yes" {attributes}>{os.path.join(PREFIX, t_dir)}</directories>\n')
                    directory += 1
            elif re.match(r'.*\</syscheck\>.*', line):
                new_conf.write('</syscheck>\n')
                syscheck_flag = False
            else:
                if not syscheck_flag:
                    new_conf.write(line)
                else:
                    continue

    setattr(sys.modules[__name__], 'n_directories', directory)

    yield

    with open(WAZUH_CONF, 'w') as o_conf:
        o_conf.writelines(original_conf)


@pytest.fixture(scope='module')
def configure_syscheck_environment(request):
    # Create every needed directory
    directories_list = list()

    for n in range(n_directories):
        t_dir = os.path.join(PREFIX, f'{testdir}{n}')
        os.makedirs(t_dir, exist_ok=True, mode=0o777)
        directories_list.append(t_dir)

    setattr(request.module, 'directories_list', directories_list)

    yield

    # Delete every created directory
    for d in directories_list:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope='module')
def generate_analysisd_yaml(request):
    def parse_events_into_yaml(event_list, yaml_file):
        with open(yaml_file, 'a')as y_f:
            for event in event_list:
                type_ev = event['data']['type'].title()
                input_ev = json.dumps(event).replace('"', '\\\"')
                del event['data']['mode']
                del event['data']['type']
                output_ev = json.dumps(event['data']).replace('"', '\\\"')

                y_f.write('-\n')
                y_f.write(f'  input: "8:[001] (vm-ubuntu-agent) 192.168.57.2->syscheck:{input_ev}"\n')
                y_f.write(f'  output: "agent 001 syscheck save2 {output_ev}"\n')
                y_f.write(f'  type: "{type_ev}"\n')

    file = 'regular'

    # Restart syscheckd with the new configuration
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('restart')

    # Wait for initial scan
    detect_initial_scan(file_monitor)

    # check_list, report_list, tags_list = parse_configurations()
    dir_list = getattr(request.module, 'directories_list')

    for directory in dir_list:
        create_file(REGULAR, directory, file, content='')
        time.sleep(0.01)
    added = wazuh_log_monitor.start(timeout=0.01 * len(dir_list), callback=callback_detect_event,
                                    accum_results=len(dir_list)).result()

    for directory in dir_list:
        modify_file(directory, file, new_content='Modified')
        time.sleep(0.01)
    modified = wazuh_log_monitor.start(timeout=0.01 * len(dir_list), callback=callback_detect_event,
                                       accum_results=len(dir_list) - 8).result()
    for directory in dir_list:
        delete_file(directory, file)
        time.sleep(0.01)
    deleted = wazuh_log_monitor.start(timeout=0.01 * len(dir_list), callback=callback_detect_event,
                                      accum_results=len(dir_list)).result()

    yaml_file = os.path.join(test_data_path, 'syscheck_events.yaml')

    # Truncate file
    with open(yaml_file, 'w')as y_f:
        y_f.write(f'---\n')

    for ev_list in [added, modified, deleted]:
        parse_events_into_yaml(ev_list, yaml_file)


# tests

@pytest.mark.parametrize('message_', [
    message_ for message_ in messages
])
def test_validate_all_alerts(configure_environment_standalone_daemons, create_unix_sockets, message_):
    """ Checks the event messages handling by analysisd.

    The variable messages is a yaml file that contains the input and the expected output for every test case.
    The function validate_analysis_integrity_state is a function responsible for checking that the output follows a
    certain jsonschema.

    """
    import pydevd_pycharm
    pydevd_pycharm.settrace('172.20.0.1', port=12345, stdoutToServer=True, stderrToServer=True)

    expected = callback_analysisd_message(message_['output'])
    receiver_sockets[0].send([message_['input']])
    response = monitored_sockets[0].start(timeout=5, callback=callback_analysisd_message).result()
    assert response == expected, 'Failed test case type: {}'.format(message_['type'])
    alert = wazuh_log_monitor.start(timeout=10, callback=callback_fim_event_alert).result()
    validate_analysis_alert(alert)
