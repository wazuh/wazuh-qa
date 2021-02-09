# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import platform
import re
import sys
import time
from datetime import timedelta

from wazuh_testing import logger
from wazuh_testing.fim import KEY_WOW64_64KEY, create_registry, delete_registry, registry_parser, \
    modify_registry_value, modify_key_perms, modify_registry_owner
from wazuh_testing.tools import WAZUH_CONF
from wazuh_testing.tools.configuration import generate_syscheck_registry_config
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.time import TimeMachine
from win32api import RegOpenKeyEx
from win32con import KEY_ALL_ACCESS, REG_SZ
from win32security import LookupAccountName

n_windows_registry = 0
reg_list = list()
KEY = "HKEY_LOCAL_MACHINE"
testreg = os.path.join('SOFTWARE', 'testreg')

SCAN_WAIT = 120


def _callback_default(line):
    print(line)
    return None


def set_syscheck_config():
    original_conf = open(WAZUH_CONF, 'r').readlines()
    registry = 0

    with open(WAZUH_CONF, 'w') as new_conf:
        syscheck_flag = False
        for line in original_conf:
            if re.match(r'.*\<syscheck\>.*', line):
                new_conf.write('<syscheck><max_eps>1000000</max_eps>\n')
                syscheck_flag = True
                for attributes in generate_syscheck_registry_config():
                    t_dir = f'{testreg}{registry}'
                    new_conf.write(f'<windows_registry arch="64bit" {attributes}>{os.path.join(KEY, t_dir)}'
                                   '</windows_registry>\n')
                    registry += 1
            elif re.match(r'.*\</syscheck\>.*', line):
                new_conf.write("<synchronization><enabled>no</enabled></synchronization>")
                new_conf.write('</syscheck>\n')
                syscheck_flag = False
            else:
                if not syscheck_flag:
                    new_conf.write(line)
                else:
                    continue

    setattr(sys.modules[__name__], 'n_windows_registry', registry)
    return original_conf


def configure_syscheck_environment(time_sleep):
    # Create every needed directory
    for n in range(n_windows_registry):
        t_dir = f'{testreg}{n}'
        create_registry(registry_parser[KEY], f'{testreg}{n}', KEY_WOW64_64KEY)
        reg_list.append(t_dir)

    control_service('restart')
    logger.debug('Waiting 15 seconds for syscheckd to start.')
    time.sleep(15)

    reg_key = 'reg_key'
    reg_value = 'value_name'

    logger.debug(f'Waiting {str(time_sleep)} seconds. Execute `generate_windows_yaml.py` now.')
    time.sleep(time_sleep)

    logger.debug(f'Waiting {SCAN_WAIT} seconds for baseline scan to finish.')
    time.sleep(120)

    logger.debug('Creating registries...')
    for registry in reg_list:
        key_h = create_registry(registry_parser[KEY], os.path.join(registry, reg_key), KEY_WOW64_64KEY)
        modify_registry_value(key_h, reg_value, REG_SZ, 'added')

    TimeMachine.travel_to_future(timedelta(hours=13))

    logger.debug(f'Waiting {SCAN_WAIT} seconds for scan to finish.')
    time.sleep(SCAN_WAIT)

    logger.debug('Modifying registries...')
    for registry in reg_list:
        modify_key_perms(registry_parser[KEY], os.path.join(registry, reg_key), KEY_WOW64_64KEY,
                         LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")[0])
        modify_registry_owner(registry_parser[KEY], os.path.join(registry, reg_key), KEY_WOW64_64KEY,
                              LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")[0])
        key_h = RegOpenKeyEx(registry_parser[KEY], os.path.join(registry, reg_key), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY)
        modify_registry_value(key_h, reg_value, REG_SZ, 'modified')

    TimeMachine.travel_to_future(timedelta(hours=13))

    logger.debug(f'Waiting {SCAN_WAIT} seconds for scan to finish.')
    time.sleep(SCAN_WAIT)

    logger.debug('Deleting registries...')
    for registry in reg_list:
        delete_registry(registry_parser[KEY], os.path.join(registry, reg_key), KEY_WOW64_64KEY)

    TimeMachine.travel_to_future(timedelta(hours=13))

    logger.debug(f'Waiting {SCAN_WAIT} seconds for scan to finish.')
    time.sleep(SCAN_WAIT)


def clean_environment(original_conf):
    control_service('stop')

    for r in reg_list:
        delete_registry(registry_parser[KEY], r, KEY_ALL_ACCESS | KEY_WOW64_64KEY)

    with open(WAZUH_CONF, 'w') as o_conf:
        o_conf.writelines(original_conf)

    control_service('start')


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
