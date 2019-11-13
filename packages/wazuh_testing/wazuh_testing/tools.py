# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import psutil
import random
import re
import string
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import yaml
from copy import deepcopy
from datetime import datetime, timedelta
from pytest import skip
from subprocess import DEVNULL, check_call
from typing import Any, List, Set


_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

if sys.platform == 'linux2' or sys.platform == 'linux':
    WAZUH_PATH = os.path.join('/', 'var', 'ossec')
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    PREFIX = os.sep

elif sys.platform == 'win32':
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    PREFIX = os.path.join('c:', os.sep)


# customize _serialize_xml to avoid lexicographical order in XML attributes

def _serialize_xml(write, elem, qnames, namespaces,
                   short_empty_elements, **kwargs):
    tag = elem.tag
    text = elem.text
    if tag is ET.Comment:
        write("<!--%s-->" % text)
    elif tag is ET.ProcessingInstruction:
        write("<?%s?>" % text)
    else:
        tag = qnames[tag]
        if tag is None:
            if text:
                write(ET._escape_cdata(text))
            for e in elem:
                _serialize_xml(write, e, qnames, None,
                               short_empty_elements=short_empty_elements)
        else:
            write("<" + tag)
            items = list(elem.items())
            if items or namespaces:
                if namespaces:
                    for v, k in sorted(namespaces.items(),
                                       key=lambda x: x[1]):  # sort on prefix
                        if k:
                            k = ":" + k
                        write(" xmlns%s=\"%s\"" % (
                            k,
                            ET._escape_attrib(v)
                            ))
                for k, v in items:  # avoid lexicographical order for XML attributes
                    if isinstance(k, ET.QName):
                        k = k.text
                    if isinstance(v, ET.QName):
                        v = qnames[v.text]
                    else:
                        v = ET._escape_attrib(v)
                    write(" %s=\"%s\"" % (qnames[k], v))
            if text or len(elem) or not short_empty_elements:
                write(">")
                if text:
                    write(ET._escape_cdata(text))
                for e in elem:
                    _serialize_xml(write, e, qnames, None,
                                   short_empty_elements=short_empty_elements)
                write("</" + tag + ">")
            else:
                write(" />")
    if elem.tail:
        write(ET._escape_cdata(elem.tail))


ET._serialize_xml = _serialize_xml  # override _serialize_xml to avoid lexicographical order in XML attributes


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
        subprocess.call(shlex.split("sudo hwclock -w"))

    @staticmethod
    def _win_set_time(time_):
        """ Changes date and time in a Windows system

        :param time_: new date and time to set
        :type time_: time
        """
        import os
        date_ = str(time_.date().day) + "-" + str(time_.date().month) + "-" + str(time_.date().year)
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
    iterations = 0
    while not condition_checker(*args, **kwargs):
        if timeout != -1 and iterations > max_iterations:
            raise TimeoutError()
        iterations += 1
        time.sleep(time_step)


def get_wazuh_conf() -> ET.ElementTree:
    """Get current 'ossec.conf' file.

    :return: ElemenTree with current Wazuh configuration
    """
    return ET.parse(WAZUH_CONF)


def write_wazuh_conf(wazuh_conf: ET.ElementTree):
    """Write a new configuration in 'ossec.conf' file."""
    return wazuh_conf.write(WAZUH_CONF, encoding='utf-8')


def set_section_wazuh_conf(section: str = 'syscheck',
                           new_elements: List = None) -> ET.ElementTree:
    """Set a configuration in a section of Wazuh. It replaces the content if it exists.
    :param section: Section of Wazuh configuration to replace
    :param new_elements: List with dictionaries for settings elements in the section
    :return: ElementTree with the custom Wazuh configuration
    """
    def create_elements(section: ET.Element, elements: List):
        """Insert new elements in a Wazuh configuration section.

        :param section: Section where the element will be inserted
        :param elements: List with the new elements to be inserted
        """
        for element in elements:
            for tag_name, properties in element.items():
                tag = ET.SubElement(section, tag_name)
                new_elements = properties.get('elements')
                if new_elements:
                    create_elements(tag, new_elements)
                else:
                    tag.text = properties.get('value')
                    attributes = properties.get('attributes')
                    if attributes:
                        for attribute in attributes:
                            if attribute is not None and isinstance(attribute, dict):  # noqa: E501
                                for attr_name, attr_value in attribute.items():
                                    tag.attrib[attr_name] = attr_value
    # get Wazuh configuration
    wazuh_conf = get_wazuh_conf()
    section_conf = wazuh_conf.find(section)
    # create section if it does not exist, clean otherwise
    if not section_conf:
        section_conf = ET.SubElement(wazuh_conf.getroot(), section)
    else:
        section_conf.clear()
    # insert elements
    if new_elements:
        create_elements(section_conf, new_elements)
    return wazuh_conf


def restart_wazuh_daemon(daemon):
    """Restarts a Wazuh daemon.

    Use this function to avoid restarting the whole service and all of its daemons.
    :param daemon string Name of the executable file of the daemon in /var/ossec/bin
    """
    for proc in psutil.process_iter(attrs=['name']):
        if proc.name() == daemon:
            proc.kill()
    check_call([f'/var/ossec/bin/{daemon}'])


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

    def _monitor(self, callback=_callback_default, accum_results=1, update_position=True):
        """Wait for new lines to be appended to the file.

        A callback function will be called every time a new line is detected. This function must receive two
        positional parameters: a references to the FileMonitor object and the line detected.
        """
        previous_position = self._position
        self._result = [] if accum_results > 1 else None
        encode = None if sys.platform == 'win32' else 'utf-8'
        with open(self.file_path, encoding=encode) as f:
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

            self._position = f.tell() if update_position else previous_position

    def start(self, timeout=-1, callback=_callback_default, accum_results=1, update_position=True):
        """Start the file monitoring until the stop method is called"""
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timer = Timer(timeout, self.abort)
                self.timer.start()
            self._monitor(callback=callback, accum_results=accum_results, update_position=update_position)

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


def random_unicode_char():
    """ Generates a random unicode char from 0x0000 to 0xD7FF

    :return: Random unicode char
    :rtype: String
    """
    return chr(random.randrange(0xD7FF))


def random_string_unicode(length, encode=None):
    """ Generates a random unicode string with variable size and optionally encoded

    :param length: String length
    :type length: Integer
    :param encode: Encoding type. Its value is None by default
    :type encode: String
    :return: Random unicode string
    :rtype: It can be a string or a binary
    """
    st = str(''.join(format(random_unicode_char()) for i in range(length)))
    st = u"".join(st)

    if encode is not None:
        st = st.encode(encode)

    return st


def random_string(length, encode=None):
    """ Generates a random alphanumeric string with variable size and optionally encoded

        :param length: String length
        :type length: Integer
        :param encode: Encoding type. Its value is None by default
        :type encode: String
        :return: Random string
        :rtype: It can be a string or a binary
        """
    letters = string.ascii_letters + string.digits
    st = str(''.join(random.choice(letters) for i in range(length)))

    if encode is not None:
        st = st.encode(encode)

    return st


def expand_placeholders(mutable_obj, placeholders=None):
    """Search for placeholders and replace them by a value inside mutable_obj

    :param mutable_obj: target object where the replacement are performed
    :param placeholders: dict where each key is a placeholder and the value is the replacement
    :return: reference to mutable_obj
    """
    placeholders = {} if placeholders is None else placeholders
    if isinstance(mutable_obj, list):
        for criterion, placeholder in placeholders.items():
            for index, value in enumerate(mutable_obj):
                if value == criterion:
                    mutable_obj[index] = placeholder
                elif isinstance(value, (dict, list)):
                    expand_placeholders(mutable_obj[index], placeholders=placeholders)
    elif isinstance(mutable_obj, dict):
        for criterion, placeholder in placeholders.items():
            for key, value in mutable_obj.items():
                if criterion == value:
                    mutable_obj[key] = placeholder
                elif isinstance(value, (dict, list)):
                    expand_placeholders(mutable_obj[key], placeholders=placeholders)

    return mutable_obj


def add_metadata(dikt, metadata=None):
    """Create a new key 'metadata' in dikt if not already exists and updates it with metadata content

    :param dikt: target dict to update metadata in
    :param metadata: dict including the new properties to be saved in the metadata key
    :return: None
    """
    if metadata is not None:
        new_metadata = dikt['metadata'] if 'metadata' in dikt else {}
        new_metadata.update(metadata)
        dikt['metadata'] = new_metadata


def process_configuration(config, placeholders=None, metadata=None):
    """Get a new configuration replacing placeholders and adding metadata.
    Both placeholders and metadata should have equal length

    :param config: dict config to be enriched
    :param placeholders: list of dicts with the replacements
    :param metadata: list of dicts with the metadata keys to include in config
    :return: dict with config enriched
    """
    new_config = expand_placeholders(deepcopy(config), placeholders=placeholders)
    add_metadata(new_config, metadata=metadata)

    return new_config


def load_wazuh_configurations(yaml_file_path: str, test_name: str, params: list = None, metadata: list = None) -> Any:
    """Load different configurations of Wazuh from a YAML file.

    :param yaml_file_path: Full path of the YAML file to be loaded
    :param test_name: Name of the file which contains the test that will be executed
    :param params: List of dicts where each dict represents a replacement MATCH -> REPLACEMENT
    :param metadata: List of dicts. Custom metadata to be inserted in the configuration
    :return: Python object with the YAML file content
    """
    params = [{}] if params is None else params
    metadata = [{}] if metadata is None else metadata
    if len(params) != len(metadata):
        raise ValueError(f"params and metadata should have the same length {len(params)} != {len(metadata)}")

    with open(yaml_file_path) as stream:
        configurations = yaml.safe_load(stream)

    return [process_configuration(configuration, placeholders=replacement, metadata=meta)
            for replacement, meta in zip(params, metadata)
            for configuration in configurations
            if test_name in expand_placeholders(configuration.get('apply_to_modules'), placeholders=replacement)]


def check_apply_test(apply_to_tags: Set, tags: List):
    """Skip test if intersection between the two parameters is empty.

    :param apply_to_tags: Tags which the tests will run
    :param tags: List with the tags which identifies a configuration
    """
    if not (apply_to_tags.intersection(tags) or
       'all' in apply_to_tags):
        skip("Does not apply to this config file")


def restart_wazuh_with_new_conf(new_conf):
    """ Restart Wazuh service applying a new ossec.conf

    :param new_conf: New config file
    :type new_conf: ElementTree
    :return: None
    """
    write_wazuh_conf(new_conf)
    if sys.platform == 'win32':
        restart_wazuh_service_windows()

    elif sys.platform == 'linux2' or sys.platform == 'linux':
        restart_wazuh_service()


def restart_wazuh_service():
    """ Restart Wazuh service completely
    :return: None
    """
    p = subprocess.Popen(["service", "wazuh-manager", "restart"])
    p.wait()


def stop_wazuh_service_windows():
    """ Stop Wazuh service completely
    :return: None
    """
    p = subprocess.Popen(["net", "stop", "OssecSvc"])
    p.wait()


def start_wazuh_service_windows():
    p = subprocess.Popen(["net", "start", "OssecSvc"])
    p.wait()


def restart_wazuh_service_windows():
    """ Restart Wazuh service completely
    :return: None
    """
    stop_wazuh_service_windows()
    start_wazuh_service_windows()


def reformat_time(scan_time):
    """ Transform scan_time to readable time

    :param scan_time: Time string
    :type scan_time: String
    :return: Datetime object
    """
    hour_format = '%H'
    colon = ''
    locale = ''
    if ':' in scan_time:
        colon = ':%M'
    if re.search('[a-zA-Z]', scan_time):
        locale = '%p'
        hour_format = '%I'
    cd = datetime.now()
    return datetime.replace(datetime.strptime(scan_time, hour_format + colon + locale),
                            year=cd.year, month=cd.month, day=cd.day)


def time_to_timedelta(time):
    """Converts a string with time in seconds with `smhdw` suffixes allowed to `datetime.timedelta`.
    """
    time_unit = time[len(time)-1:]

    if time_unit.isnumeric():
        return timedelta(seconds=int(time))

    time_value = int(time[:len(time)-1])

    if time_unit == "s":
        return timedelta(seconds=time_value)
    elif time_unit == "m":
        return timedelta(minutes=time_value)
    elif time_unit == "h":
        return timedelta(hours=time_value)
    elif time_unit == "d":
        return timedelta(days=time_value)
    elif time_unit == "w":
        return timedelta(weeks=time_value)
