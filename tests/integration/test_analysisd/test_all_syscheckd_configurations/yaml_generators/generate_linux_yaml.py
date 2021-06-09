# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import json
import os
import re
import shutil
import sys
import time

import yaml
from wazuh_testing import logger
from wazuh_testing.analysis import callback_analysisd_agent_id, callback_analysisd_event
from wazuh_testing.fim import REGULAR, create_file, modify_file, delete_file, detect_initial_scan
from wazuh_testing.tools import WAZUH_LOGS_PATH, LOG_FILE_PATH, WAZUH_PATH, WAZUH_CONF, PREFIX
from wazuh_testing.tools.configuration import generate_syscheck_config
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import ManInTheMiddle, QueueMonitor, FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status, delete_sockets

alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue'))

# Syscheck variables
n_directories = 0
directories_list = list()
testdir = 'testdir'
yaml_file = 'syscheck_events.yaml'


def set_syscheck_config():
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
    return original_conf


def set_syscheck_backup(original_conf):
    with open(WAZUH_CONF, 'w') as o_conf:
        o_conf.writelines(original_conf)


def create_syscheck_environment():
    # Create every needed directory
    for n in range(n_directories):
        t_dir = os.path.join(PREFIX, f'{testdir}{n}')
        os.makedirs(t_dir, exist_ok=True, mode=0o777)
        directories_list.append(t_dir)


def clean_syscheck_environment():
    # Delete every created directory
    for d in directories_list:
        shutil.rmtree(d, ignore_errors=True)


def generate_analysisd_yaml(n_events, modify_events):
    def parse_events_into_yaml(requests, yaml_file):
        yaml_result = []
        with open(yaml_file, 'a') as y_f:
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

    def remove_logs():
        for root, dirs, files in os.walk(WAZUH_LOGS_PATH):
            for file in files:
                os.remove(os.path.join(root, file))

    file = 'regular'

    # Restart syscheckd with the new configuration
    truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    control_service('stop')
    check_daemon_status(running_condition=False)
    remove_logs()

    control_service('start', daemon='wazuh-db', debug_mode=True)
    check_daemon_status(running_condition=True, target_daemon='wazuh-db')

    control_service('start', daemon='wazuh-analysisd', debug_mode=True)
    check_daemon_status(running_condition=True, target_daemon='wazuh-analysisd')

    mitm_analysisd = ManInTheMiddle(address=analysis_path, family='AF_UNIX', connection_protocol='UDP')
    analysis_queue = mitm_analysisd.queue
    mitm_analysisd.start()

    control_service('start', daemon='wazuh-syscheckd', debug_mode=True)
    check_daemon_status(running_condition=True, target_daemon='wazuh-syscheckd')

    # Wait for initial scan
    detect_initial_scan(file_monitor)

    analysis_monitor = QueueMonitor(analysis_queue)

    for directory in directories_list:
        create_file(REGULAR, directory, file, content='')
        time.sleep(0.01)
    added = analysis_monitor.start(timeout=max(0.01 * n_events, 10), callback=callback_analysisd_event,
                                   accum_results=len(directories_list)).result()
    logger.debug('"added" alerts collected.')

    for directory in directories_list:
        modify_file(directory, file, new_content='Modified')
        time.sleep(0.01)
    modified = analysis_monitor.start(timeout=max(0.01 * n_events, 10), callback=callback_analysisd_event,
                                      accum_results=modify_events).result()
    logger.debug('"modified" alerts collected.')

    for directory in directories_list:
        delete_file(directory, file)
        time.sleep(0.01)
    deleted = analysis_monitor.start(timeout=max(0.01 * len(directories_list), 10), callback=callback_analysisd_event,
                                     accum_results=len(directories_list)).result()
    logger.debug('"deleted" alerts collected.')

    # Truncate file
    with open(yaml_file, 'w')as y_f:
        y_f.write(f'---\n')

    for ev_list in [added, modified, deleted]:
        parse_events_into_yaml(ev_list, yaml_file)
    logger.debug(f'YAML done: "{yaml_file}"')

    return mitm_analysisd


def kill_daemons():
    for daemon in ['wazuh-analysisd', 'wazuh-db', 'wazuh-syscheckd']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running_condition=False, target_daemon=daemon)


def get_script_arguments():
    list_of_choices = ['DEBUG', 'ERROR']
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Analysisd YAML generator (Linux)",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-e', '--events', dest='n_events', default=4096,
                        help='Specify how many events will be expected to be created and deleted. Default 4096.',
                        action='store')
    parser.add_argument('-m', '--modified', dest='modified_events', default=4088,
                        help='Specify how many modified events will be expected. Default 4088.', action='store')
    parser.add_argument('-d', '--debug', dest='debug_level', default='ERROR', choices=list_of_choices,
                        help='Specify debug level. Default "ERROR".', action='store')
    return parser.parse_args()


if __name__ == '__main__':
    log_level = {'DEBUG': 10, 'ERROR': 40}

    options = get_script_arguments()
    events = int(options.n_events)
    modified = int(options.modified_events)
    logger.setLevel(log_level[options.debug_level])

    original_conf = set_syscheck_config()
    create_syscheck_environment()
    try:
        mitm = generate_analysisd_yaml(n_events=events, modify_events=modified)
        mitm.shutdown()
    except FileNotFoundError:
        logger.error('Could not generate the YAML. Please clean the environment.')
        delete_sockets()
    except TimeoutError:
        logger.error('Timeout generating necessary events. Please clean the environment.')
    finally:
        set_syscheck_backup(original_conf)
        clean_syscheck_environment()
        kill_daemons()
        control_service('start')
