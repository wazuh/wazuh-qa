# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
import shutil
import time
from collections import defaultdict

import pytest
import yaml

from wazuh_testing.analysis import callback_analysisd_event, callback_analysisd_agent_id, callback_fim_alert
from wazuh_testing.fim import detect_initial_scan, REGULAR, create_file, modify_file, delete_file
from wazuh_testing.tools import WAZUH_CONF, PREFIX, LOG_FILE_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.configuration import generate_syscheck_config
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, ManInTheMiddle, QueueMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture(scope='module')
def set_syscheck_config(request):
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

    setattr(request.module, 'n_directories', directory)

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
    def parse_events_into_yaml(requests, yaml_file_):
        yaml_result = []
        with open(yaml_file_, 'a') as y_f:
            id_ev = 0
            for req, event in requests:
                type_ev = event['data']['type']
                stage_ev = type_ev.title()
                mode = None
                agent_id = callback_analysisd_agent_id(req) or '000'

                del event['data']['mode']
                del event['data']['type']
                if 'tags' in event['data']:
                    del event['data']['tags']
                if type_ev == 'added':
                    mode = 'save2'
                    output_ev = json.dumps(event['data'])

                elif type_ev == 'deleted':
                    mode = 'delete'
                    output_ev = json.dumps(event['data']['path']).replace('"', '')

                elif type_ev == 'modified':
                    mode = 'save2'
                    for field in ['old_attributes', 'changed_attributes', 'content_changes']:
                        if field in event['data']:
                            del event['data'][field]
                    output_ev = json.dumps(event['data'])

                yaml_result.append({
                    'name': f"{stage_ev}{id_ev}",
                    'test_case': [
                        {
                            'input': f"{req}",
                            'output': f"agent {agent_id} syscheck {mode} {output_ev}",
                            'stage': f"{stage_ev}"
                        }
                    ]
                })
                id_ev += 1
            y_f.write(yaml.safe_dump(yaml_result))

    file = 'regular'

    # Restart syscheckd with the new configuration
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('stop')



    control_service('start', daemon='wazuh-db', debug_mode=True)
    check_daemon_status(running=True, daemon='wazuh-db')

    control_service('start', daemon='ossec-analysisd', debug_mode=True)
    check_daemon_status(running=True, daemon='ossec-analysisd')

    analysis_path = getattr(request.module, 'analysis_path')
    mitm_analysisd = ManInTheMiddle(analysis_path, mode='UDP')
    analysis_queue = mitm_analysisd.queue
    mitm_analysisd.start()

    control_service('start', daemon='ossec-syscheckd', debug_mode=True)
    check_daemon_status(running=True, daemon='ossec-syscheckd')

    # Wait for initial scan
    detect_initial_scan(file_monitor)

    # check_list, report_list, tags_list = parse_configurations()
    dir_list = getattr(request.module, 'directories_list')

    analysis_monitor = QueueMonitor(analysis_queue)

    for directory in dir_list:
        create_file(REGULAR, directory, file, content='')
        time.sleep(0.01)
    added = analysis_monitor.start(timeout=0.01 * len(dir_list), callback=callback_analysisd_event,
                                   accum_results=len(dir_list)).result()

    for directory in dir_list:
        modify_file(directory, file, new_content='Modified')
        time.sleep(0.01)
    modified = analysis_monitor.start(timeout=0.01 * len(dir_list), callback=callback_analysisd_event,
                                      accum_results=len(dir_list)-8).result()
    for directory in dir_list:
        delete_file(directory, file)
        time.sleep(0.01)
    deleted = analysis_monitor.start(timeout=0.01 * len(dir_list), callback=callback_analysisd_event,
                                     accum_results=len(dir_list)).result()

    test_data_path = getattr(request.module, 'test_data_path')
    yaml_file = os.path.join(test_data_path, 'syscheck_events.yaml')

    # Truncate file
    with open(yaml_file, 'w')as y_f:
        y_f.write(f'---\n')

    for ev_list in [added, modified, deleted]:
        parse_events_into_yaml(ev_list, yaml_file)

    yield

    mitm_analysisd.shutdown()

    for daemon in ['ossec-analysisd', 'wazuh-db', 'ossec-syscheckd']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running=False, daemon=daemon)


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = getattr(request.module, 'wazuh_log_monitor')
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)


@pytest.fixture(scope='module')
def configure_mitm_environment_analysisd(request):
    def remove_logs():
        """Remove all Wazuh logs"""
        for root, dirs, files in os.walk(WAZUH_LOGS_PATH):
            for file in files:
                os.remove(os.path.join(root, file))

    analysis_path = getattr(request.module, 'analysis_path')
    wdb_path = getattr(request.module, 'wdb_path')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running=False)
    remove_logs()

    control_service('start', daemon='wazuh-db', debug_mode=True)
    check_daemon_status(running=True, daemon='wazuh-db')

    mitm_wdb = ManInTheMiddle(socket_path=wdb_path)
    wdb_queue = mitm_wdb.queue
    mitm_wdb.start()

    control_service('start', daemon='ossec-analysisd', debug_mode=True)
    check_daemon_status(running=True, daemon='ossec-analysisd')

    mitm_analysisd = ManInTheMiddle(socket_path=analysis_path, mode='UDP')
    analysisd_queue = mitm_analysisd.queue
    mitm_analysisd.start()

    analysis_monitor = QueueMonitor(queue_item=analysisd_queue)
    wdb_monitor = QueueMonitor(queue_item=wdb_queue)

    setattr(request.module, 'analysis_monitor', analysis_monitor)
    setattr(request.module, 'wdb_monitor', wdb_monitor)

    yield

    mitm_analysisd.shutdown()
    mitm_wdb.shutdown()

    for daemon in ['wazuh-db', 'ossec-analysisd']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running=False, daemon=daemon)


@pytest.fixture(scope='module')
def generate_events_and_alerts(request):
    alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
    test_cases = getattr(request.module, 'test_cases')
    socket_controller = getattr(request.module, 'receiver_sockets')[0]
    events = defaultdict(dict)
    ips = getattr(request.module, 'analysisd_injections_per_second')

    alert_monitor = FileMonitor(alerts_json)

    for test_case in test_cases:
        case = test_case['test_case'][0]
        event = (json.loads(re.match(r'(.*)syscheck:(.+)$', case['input']).group(2)))
        events[event['data']['path']].update({case['stage']: event})
        socket_controller.send([case['input']])
        time.sleep(1 / ips)

    n_alerts = len(test_cases)
    time.sleep(3)
    alerts = alert_monitor.start(timeout=max(n_alerts * 0.001, 15), callback=callback_fim_alert,
                                 accum_results=n_alerts).result()

    setattr(request.module, 'alerts_list', alerts)
    setattr(request.module, 'events_dict', events)
