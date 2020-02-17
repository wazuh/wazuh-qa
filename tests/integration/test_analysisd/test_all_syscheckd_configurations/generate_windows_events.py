# Copyright (C) 2015-2020, Wazuh Inc.
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
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.time import Timer

n_directories = 0
directories_list = list()
testdir = 'testdir'


def _callback_default(line):
    print(line)
    return None


class FileMonitor:

    def __init__(self, file_path, time_step=0.5):
        self.file_path = file_path
        self._position = 0
        self.time_step = time_step
        self._continue = False
        self._abort = False
        self._previous_event = None
        self._result = None
        self.timeout_timer = None
        self.extra_timer = None
        self.extra_timer_is_running = False

    def _monitor(self, callback=_callback_default, accum_results=1, update_position=True, timeout_extra=0,
                 encoding=None):
        """Wait for new lines to be appended to the file.
        A callback function will be called every time a new line is detected. This function must receive two
        positional parameters: a references to the FileMonitor object and the line detected.
        """
        previous_position = self._position
        if sys.platform == 'win32':
            encoding = None if encoding is None else encoding
        elif encoding is None:
            encoding = 'utf-8'
        self.extra_timer_is_running = False
        self._result = [] if accum_results > 1 or timeout_extra > 0 else None
        with open(self.file_path, encoding=encoding) as f:
            f.seek(self._position)
            while self._continue:
                if self._abort and not self.extra_timer_is_running:
                    self.stop()
                    if type(self._result) != list or accum_results != len(self._result):
                        raise TimeoutError()
                self._position = f.tell()
                line = f.readline()
                if not line:
                    f.seek(self._position)
                    time.sleep(self.time_step)
                else:
                    result = callback(line)
                    if result:
                        if type(self._result) == list:
                            self._result.append(result)
                            if accum_results == len(self._result):
                                if timeout_extra > 0 and not self.extra_timer_is_running:
                                    self.extra_timer = Timer(timeout_extra, self.stop)
                                    self.extra_timer.start()
                                    self.extra_timer_is_running = True
                                elif timeout_extra == 0:
                                    self.stop()
                        else:
                            self._result = result
                            if self._result:
                                self.stop()
            self._position = f.tell() if update_position else previous_position

    def start(self, timeout=-1, callback=_callback_default, accum_results=1, update_position=True, timeout_extra=0,
              encoding=None):
        """Start the file monitoring until the stop method is called."""
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timeout_timer = Timer(timeout, self.abort)
                self.timeout_timer.start()
            self._monitor(callback=callback, accum_results=accum_results, update_position=update_position,
                          timeout_extra=timeout_extra, encoding=encoding)

        return self

    def stop(self):
        """Stop the file monitoring. It can be restart calling the start method."""
        self._continue = False
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer.join()
        if self.extra_timer and self.extra_timer_is_running:
            self.extra_timer.cancel()
            self.extra_timer_is_running = False
        return self

    def abort(self):
        """Abort because of timeout."""
        self._abort = True
        return self

    def result(self):
        return self._result


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
