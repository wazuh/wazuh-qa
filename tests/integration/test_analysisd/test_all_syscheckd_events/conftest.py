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

from wazuh_testing.fim import detect_initial_scan, REGULAR, create_file, callback_detect_event, modify_file, delete_file
from wazuh_testing.tools import WAZUH_CONF, PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import generate_syscheck_config
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service


@pytest.fixture(scope='module')
def set_syscheck_config(request):
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('172.20.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    original_conf = open(WAZUH_CONF, 'r').readlines()
    directory = 0
    testdir = getattr(request.module, 'testdir')

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
    testdir = getattr(request.module, 'testdir')
    n_directories = getattr(request.module, 'n_directories')

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
    def parse_events_into_yaml(event_list, yaml_file_):
        with open(yaml_file_, 'a')as y_f:
            id_ev = 0
            for event in event_list:
                stage_ev = event['data']['type'].title()
                input_ev = json.dumps(event).replace('"', '\\\"')
                del event['data']['mode']
                del event['data']['type']
                if 'tags' in event['data']:
                    del event['data']['tags']
                output_ev = json.dumps(event['data']).replace('"', '\\\"')

                y_f.write(f'-\n  name: "{stage_ev}{id_ev}"\n  test_case:\n')
                y_f.write('  -\n')
                y_f.write(f'    input: "8:[001] (vm-ubuntu-agent) 192.168.57.2->syscheck:{input_ev}"\n')
                y_f.write(f'    output: "agent 001 syscheck save2 {output_ev}"\n')
                y_f.write(f'    stage: "{stage_ev}"\n')
                id_ev += 1

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
    added = file_monitor.start(timeout=0.01 * len(dir_list), callback=callback_detect_event,
                               accum_results=len(dir_list)).result()

    for directory in dir_list:
        modify_file(directory, file, new_content='Modified')
        time.sleep(0.01)
    modified = file_monitor.start(timeout=0.01 * len(dir_list), callback=callback_detect_event,
                                  accum_results=len(dir_list) - 8).result()
    for directory in dir_list:
        delete_file(directory, file)
        time.sleep(0.01)
    deleted = file_monitor.start(timeout=0.01 * len(dir_list), callback=callback_detect_event,
                                 accum_results=len(dir_list)).result()

    test_data_path = getattr(request.module, 'test_data_path')
    yaml_file = os.path.join(test_data_path, 'syscheck_events.yaml')

    # Truncate file
    with open(yaml_file, 'w')as y_f:
        y_f.write(f'---\n')

    for ev_list in [added, modified, deleted]:
        parse_events_into_yaml(ev_list, yaml_file)


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = getattr(request.module, 'wazuh_log_monitor')
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)
