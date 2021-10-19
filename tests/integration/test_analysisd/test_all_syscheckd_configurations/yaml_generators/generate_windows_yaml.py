# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import json
import logging
import os
import subprocess
import time

import yaml
from wazuh_testing import logger
from wazuh_testing.analysis import callback_analysisd_agent_id, callback_analysisd_event
from wazuh_testing.tools import WAZUH_LOGS_PATH, LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import ManInTheMiddle, QueueMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status, delete_sockets

alerts_json = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
analysis_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue'))

# Syscheck variables
n_directories = 0
testdir = 'testdir'
yaml_file = 'syscheck_events_win32.yaml'
expected_deleted = None


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
        for root, _, files in os.walk(WAZUH_LOGS_PATH):
            for file in files:
                os.remove(os.path.join(root, file))

    # Restart syscheckd with the new configuration
    truncate_file(LOG_FILE_PATH)
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

    control_service('start', daemon='wazuh-remoted', debug_mode=True)
    check_daemon_status(running_condition=True, target_daemon='wazuh-remoted')

    analysis_monitor = QueueMonitor(analysis_queue)

    while True:
        try:
            grep = subprocess.Popen(['grep', 'deleted', alerts_json], stdout=subprocess.PIPE)
            wc = int(subprocess.check_output(['wc', '-l', ], stdin=grep.stdout).decode())
        except subprocess.CalledProcessError:
            wc = 0
        if wc >= n_events:
            logging.debug('All alerts received. Collecting by alert type...')
            break
        logger.debug(f'{wc} deleted events so far.')
        logger.debug('Waiting for alerts. Sleeping 5 seconds.')
        time.sleep(5)

    added = analysis_monitor.start(timeout=max(0.01 * n_events, 10), callback=callback_analysisd_event,
                                   accum_results=n_events).result()
    logger.debug('"added" alerts collected.')

    modified = analysis_monitor.start(timeout=max(0.01 * n_events, 10), callback=callback_analysisd_event,
                                      accum_results=modify_events).result()
    logger.debug('"modified" alerts collected.')

    deleted = analysis_monitor.start(timeout=max(0.01 * n_events, 10), callback=callback_analysisd_event,
                                     accum_results=n_events).result()
    logger.debug('"deleted" alerts collected.')

    # Truncate file
    with open(yaml_file, 'w')as y_f:
        y_f.write('---\n')

    for ev_list in [added, modified, deleted]:
        parse_events_into_yaml(ev_list, yaml_file)
    logger.debug(f'YAML done: "{yaml_file}"')

    return mitm_analysisd


def kill_daemons():
    for daemon in ['wazuh-remoted', 'wazuh-analysisd', 'wazuh-db']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running_condition=False, target_daemon=daemon)


def get_script_arguments():
    list_of_choices = ['DEBUG', 'ERROR']
    parser = argparse.ArgumentParser(usage="python3 %(prog)s [options]",
                                     description="Analysisd YAML generator (Windows)",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-e', '--events', dest='n_events', default=4096, type=int,
                        help='Specify how many events will be expected. Default 4096.', action='store')
    parser.add_argument('-m', '--modified', dest='modified_events', default=4080, type=int,
                        help='Specify how many modified events will be expected. Default 4080.', action='store')
    parser.add_argument('-d', '--debug', dest='debug_level', default='ERROR', choices=list_of_choices,
                        help='Specify debug level. Default "ERROR".', action='store')
    return parser.parse_args()


if __name__ == '__main__':
    log_level = {'DEBUG': 10, 'ERROR': 40}

    options = get_script_arguments()
    events = options.n_events
    modified = options.modified_events
    logger.setLevel(log_level[options.debug_level])

    try:
        mitm = generate_analysisd_yaml(n_events=events, modify_events=modified)
        mitm.shutdown()
    except (TimeoutError, FileNotFoundError) as e:
        logger.error(f'Could not generate the YAML. Please clean the environment.{e}')
        delete_sockets()
    finally:
        kill_daemons()
        control_service('start')
