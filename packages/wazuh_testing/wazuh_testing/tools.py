# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import time
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from subprocess import DEVNULL, check_call, check_output
from typing import List


WAZUH_PATH = os.path.join('/', 'var', 'ossec')
WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
WAZUH_SOURCES = os.path.join('/', 'wazuh')
GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')


class TimeMachine:
    """ Context manager that goes forward/back in time and comes back to real time once it finishes its instance
    """

    def __init__(self, timedelta):
        """ Saves time frame given by user

        :param timedelta: time frame
        :type timedelta: timedelta
        """
        self.time_delta = timedelta

    def __enter__(self):
        """ Calls travel_to_future function with saved timedelta as argument
        """
        self.travel_to_future(self.time_delta)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """ Calls travel_to_future again before exiting with a negative timedelta
        """
        self.travel_to_future(self.time_delta * -1)

    @staticmethod
    def _linux_set_time(time_):
        """ Changes date and time in a Linux system

        :param time_: new date and time to set
        :type time_: time
        """
        import subprocess
        import shlex
        subprocess.call(shlex.split("timedatectl set-ntp false"))
        subprocess.call(shlex.split("sudo date -s '%s'" % time_))

    @staticmethod
    def _win_set_time(time_):
        """ Changes date and time in a Windows system

        :param time_: new date and time to set
        :type time_: time
        """
        import os
        date_ = str(time_.date())
        time_ = str(time_.time()).split('.')
        time_ = time_[0]
        os.system('date ' + date_)
        os.system('time ' + time_)

    @staticmethod
    def travel_to_future(time_delta):
        """ Checks which system are we running this code in and calls its proper function

        :param time_delta: time frame we want to skip. It can have a negative value
        :type time_delta: timedelta
        """
        future = datetime.now() + time_delta
        if sys.platform == 'linux2' or sys.platform == 'linux':
            TimeMachine._linux_set_time(future.isoformat())
        elif sys.platform == 'win32':
            TimeMachine._win_set_time(future)


class TestEnvironment:
    """Class to prepare a custom configuration for a test."""

    def __init__(self, section: str, new_elements: List,
                 checks: List = None) -> None:
        """Initialize TestEnvironment class.

        :param section: Section of 'ossec.conf' to edit
        :param new_elements: List with dictionaries for replacing element values in a section
        :param checks: List with different checks for testing the environment
        """
        self.backup_conf = get_wazuh_conf()
        self.section = section
        self.new_elements = new_elements
        self.checks = checks
        self.new_conf = set_section_configuration(self.section,
                                                  self.new_elements)


def set_wazuh_conf(wazuh_conf: ET.ElementTree):
    """Set up Wazuh configuration. Wazuh will be restarted for applying it."""
    write_wazuh_conf(wazuh_conf)
    print("Restarting Wazuh...")
    command = os.path.join(WAZUH_PATH, 'bin/ossec-control')
    arguments = ['restart']
    check_call([command] + arguments, stdout=DEVNULL, stderr=DEVNULL)


def truncate_file(file_path):
    with open(file_path, 'w'):
        pass


def wait_for_condition(condition_checker, args=None, kwargs=None, timeout=-1):
    args = [] if args is None else args
    kwargs = {} if kwargs is None else kwargs
    time_step = 0.5
    max_iterations = timeout / time_step
    begin = time.time()
    iterations = 0
    while not condition_checker(*args, **kwargs):
        if timeout != -1 and iterations > max_iterations:
            raise TimeoutError()
        iterations += 1
        time.sleep(time_step)


def generate_wazuh_conf(args: List = None) -> ET.ElementTree:
    """Generate a configuration file for Wazuh.

    :param args: Arguments for generating ossec.conf (install_type, distribution, version)
    :return: ElementTree with a new Wazuh configuration generated from 'gen_ossec.sh'
    """
    gen_ossec_args = args if args else ['conf', 'manager', 'rhel', '7']
    wazuh_config = check_output([GEN_OSSEC] + gen_ossec_args).decode(encoding='utf-8', errors='ignore')

    return ET.ElementTree(ET.fromstring(wazuh_config))


def get_wazuh_conf() -> ET.ElementTree:
    """Get current 'ossec.conf' file.

    :return: ElemenTree with current Wazuh configuration
    """
    return ET.parse(WAZUH_CONF)


def write_wazuh_conf(wazuh_conf: ET.ElementTree):
    """Write a new configuration in 'ossec.conf' file."""
    return wazuh_conf.write(WAZUH_CONF, encoding='utf-8')


def set_section_configuration(section: str = 'syscheck',
                              new_elements: List = None) -> ET.ElementTree:
    """Set a configuration in a section of Wazuh. It replaces the content if it exists.

    :param wazuh_conf: XML with the Wazuh configuration (ossec.conf)
    :param new_elements: List with dictionaries for settings elements
    :return: ElementTree with the custom Wazuh configuration
    """
    wazuh_conf = get_wazuh_conf()
    section_conf = wazuh_conf.find('/'.join([section]))
    # create section if it does not exist, clean otherwise
    if not section_conf:
        section_conf = ET.SubElement(wazuh_conf.getroot(), section)
    else:
        section_conf.clear()
    # insert elements
    if new_elements:
        for elem in new_elements:
            for tag_name, properties in elem.items():
                tag = ET.SubElement(section_conf, tag_name)
                tag.text = properties.get('value')
                attributes = properties.get('attributes')
                if attributes:
                    for attr_name, attr_value in attributes.items():
                        tag.attrib[attr_name] = attr_value

    return wazuh_conf


def _callback_default(line):
    print(line)
    return None


class Timer(threading.Thread):

    def __init__(self, timeout=10, function=None, time_step=0.5):
        threading.Thread.__init__(self)
        self.timeout = timeout
        self.function = function
        self.time_step = time_step
        self._cancel = threading.Event()

    def run(self):
        max_iterations = int(self.timeout / self.time_step)
        for i in range(max_iterations):
            time.sleep(self.time_step)
            if self.is_canceled():
                return
        self.function()
        return

    def cancel(self):
        self._cancel.set()

    def is_canceled(self):
        return self._cancel.is_set()


class FileMonitor:

    def __init__(self, file_path, time_step=0.5):
        self.file_path = file_path
        self._position = 0
        self.time_step = time_step
        self._continue = False
        self._abort = False
        self._result = None
        self.timer = None

    def _monitor(self, callback=_callback_default, accum_results=1):
        """Wait for new lines to be appended to the file.

        A callback function will be called every time a new line is detected. This function must receive two
        positional parameters: a references to the FileMonitor object and the line detected.
        """
        self._result = [] if accum_results > 1 else None
        with open(self.file_path) as f:
            f.seek(self._position)
            while self._continue:
                if self._abort:
                    self.stop()
                    raise TimeoutError()
                self._position = f.tell()
                line = f.readline()
                if not line:
                    f.seek(self._position)
                    time.sleep(self.time_step)
                else:
                    result = callback(line)
                    if result:
                        if accum_results > 1:
                            self._result.append(result)
                            if accum_results == len(self._result):
                                self.stop()
                        else:
                            self._result = result
                            if self._result:
                                self.stop()

            self._position = f.tell()

    def start(self, timeout=-1, callback=_callback_default, accum_results=1):
        """Start the file monitoring until the stop method is called"""
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timer = Timer(timeout, self.abort)
                self.timer.start()
            self._monitor(callback=callback, accum_results=accum_results)

        return self

    def stop(self):
        """Stop the file monitoring. It can be restart calling the start method"""
        self._continue = False
        if self.timer:
            self.timer.cancel()
            self.timer.join()
        return self

    def abort(self):
        """Abort because of timeout"""
        self._abort = True
        return self

    def result(self):
        return self._result
