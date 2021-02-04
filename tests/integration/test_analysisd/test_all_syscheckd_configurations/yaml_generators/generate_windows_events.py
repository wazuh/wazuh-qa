# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import re
import shutil
import sys
import time

from wazuh_testing import logger
from wazuh_testing.fim import REGULAR, create_file, modify_file, delete_file, callback_detect_event
from wazuh_testing.tools import WAZUH_CONF, PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import generate_syscheck_config
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

n_directories = 0
directories_list = list()
testdir = 'testdir'


def _callback_default(line):
    print(line)
    return None


def set_syscheck_config():
    original_conf = open(WAZUH_CONF, 'r').readlines()
    directory = 0

    with open(WAZUH_CONF, 'w') as new_conf:
        syscheck_flag = False
        for line in original_conf:
            if re.match(r'.*\<syscheck\>.*', line):
                new_conf.write('<syscheck><max_eps>1000000</max_eps>\n')
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


def configure_syscheck_environment(time_sleep):
    # Create every needed directory
    for n in range(n_directories):
        t_dir = os.path.join(PREFIX, f'{testdir}{n}')
        os.makedirs(t_dir, exist_ok=True, mode=0o777)
        directories_list.append(t_dir)

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    control_service('restart')
    logger.debug('Waiting 15 seconds for syscheckd to start.')
    time.sleep(15)

    file = 'regular'

    logger.debug(f'Waiting {str(time_sleep)} seconds. Execute `generate_windows_yaml.py` now.')
    time.sleep(time_sleep)

    logger.debug('Creating files...')
    for directory in directories_list:
        create_file(REGULAR, directory, file, content='')
        time.sleep(0.01)
    try:
        while True:
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
    except TimeoutError:
        pass

    logger.debug('Modifying files...')
    for directory in directories_list:
        modify_file(directory, file, new_content='Modified')
        time.sleep(0.01)
    try:
        while True:
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
    except TimeoutError:
        pass

    logger.debug('Deleting files...')
    for directory in directories_list:
        delete_file(directory, file)
        time.sleep(0.01)
    try:
        while True:
            wazuh_log_monitor.start(timeout=5, callback=callback_detect_event)
    except TimeoutError:
        pass


def clean_environment(original_conf):
    control_service('stop')

    for d in directories_list:
        shutil.rmtree(d, ignore_errors=True)

    with open(WAZUH_CONF, 'w') as o_conf:
        o_conf.writelines(original_conf)


def get_script_arguments():
    list_of_choices = ['DEBUG', 'ERROR']
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Syscheck event generator (Windows)",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--time', dest='time_sleep', default=5,
                        help='Time to sleep until the events will be generated. Default 5.', action='store')
    parser.add_argument('-d', '--debug', dest='debug_level', default='ERROR', choices=list_of_choices,
                        help='Specify debug level. Default "ERROR".', action='store')
    return parser.parse_args()


if __name__ == '__main__':
    log_level = {'DEBUG': 10, 'ERROR': 40}

    options = get_script_arguments()
    time_sleep = int(options.time_sleep)
    logger.setLevel(log_level[options.debug_level])

    original_conf = set_syscheck_config()
    configure_syscheck_environment(time_sleep)
    clean_environment(original_conf)
