# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import random
import re
import socket
import string
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from copy import deepcopy
from datetime import datetime, timedelta
from struct import pack, unpack
from subprocess import DEVNULL, check_call, check_output
from typing import Any, List, Set

import psutil
import yaml
from pytest import skip

if sys.platform == 'win32':
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    PREFIX = os.path.join('c:', os.sep)

elif sys.platform == 'darwin':
    WAZUH_PATH = os.path.join('/', 'Library', 'Ossec')
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    PREFIX = os.sep

else:
    WAZUH_PATH = os.path.join('/', 'var', 'ossec')
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')
    PREFIX = os.sep

if sys.platform == 'darwin' or sys.platform == 'win32' or sys.platform == 'sunos5':
    WAZUH_SERVICE = 'wazuh.agent'
else:
    with open(os.path.join(WAZUH_PATH, 'etc/ossec-init.conf'), 'r') as f:
        type_ = None
        for line in f.readlines():
            if 'TYPE' in line:
                type_ = line.split('"')[1]
        WAZUH_SERVICE = 'wazuh-manager' if type_ == 'server' else 'wazuh-agent'

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
WAZUH_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')


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
    def _linux_set_time(datetime_):
        """ Changes date and time in a Linux system

        :param datetime_: new date and time to set
        :type datetime_: time
        """
        import shlex
        subprocess.call(shlex.split("timedatectl set-ntp false"))
        subprocess.call(shlex.split("sudo date -s '%s'" % datetime_))
        subprocess.call(shlex.split("sudo hwclock -w"))

    @staticmethod
    def _win_set_time(datetime_):
        """ Changes date and time in a Windows system

        :param datetime_: new date and time to set
        :type datetime_: time
        """
        os.system('date ' + datetime_.strftime("%d-%m-%Y"))
        os.system('time ' + datetime_.strftime("%H:%M:%S"))

    @staticmethod
    def _solaris_set_time(datetime_):
        """ Changes date and time in a Linux system

        :param datetime_: new date and time to set
        :type datetime_: time
        """
        solaris_time_format = "%m%d%H%M%Y.%S"
        os.system("date '%s'" % datetime_.strftime(solaris_time_format))

    @staticmethod
    def _macos_set_time(datetime_):
        """ Changes date and time in a MacOS system

        :param datetime_: new date and time to set
        :type datetime_: time
        """
        # {month}{day}{hour}{minute}{year}
        os.system('date ' + '-u ' + datetime_.strftime("%m%d%H%M%Y"))

    @staticmethod
    def travel_to_future(time_delta):
        """ Checks which system are we running this code in and calls its proper function

        :param time_delta: time frame we want to skip. It can have a negative value
        :type time_delta: timedelta
        """
        now = datetime.utcnow() if sys.platform == 'darwin' else datetime.now()
        future = now + time_delta
        if sys.platform == 'linux':
            TimeMachine._linux_set_time(future.isoformat())
        elif sys.platform == 'sunos5':
            TimeMachine._solaris_set_time(future)
        elif sys.platform == 'win32':
            TimeMachine._win_set_time(future)
        elif sys.platform == 'darwin':
            TimeMachine._macos_set_time(future)


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
                    tag.text = str(properties.get('value'))
                    attributes = properties.get('attributes')
                    if attributes:
                        for attribute in attributes:
                            if attribute is not None and isinstance(attribute, dict):  # noqa: E501
                                for attr_name, attr_value in attribute.items():
                                    tag.attrib[attr_name] = str(attr_value)
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

    daemon_path = os.path.join(WAZUH_PATH, 'bin')
    check_call([f'{daemon_path}/{daemon}'])


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


def restart_wazuh_with_new_conf(new_conf, daemon='ossec-syscheckd'):
    """ Restart Wazuh service applying a new ossec.conf

    :param new_conf: New config file
    :type new_conf: ElementTree
    :return: None
    """
    write_wazuh_conf(new_conf)
    control_service('restart', daemon=daemon)


def control_service(action, daemon=None, debug_mode=False):
    """Performs the stop, start and restart operation with Wazuh.
    It takes care of the current OS to interact with the service and the type of installation (agent or manager)

    Parameters
    ----------
    action : str
        Must be one of 'stop', 'start' or 'restart'
    daemon : str
        Name of the daemon to be controlled. None to control the whole Wazuh service
    debug_mode : bool
        Run the specified daemon in debug mode

    """
    valid_actions = ('start', 'stop', 'restart')
    if action not in valid_actions:
        raise ValueError(f'action {action} is not one of {valid_actions}')

    if sys.platform == 'win32':
        if action == 'restart':
            control_service('stop')
            control_service('start')
            result = 0
        else:
            result = 0 if subprocess.run(["net", action, "OssecSvc"]).returncode in (0, 2) else \
                subprocess.run(["net", action, "OssecSvc"]).returncode
    else:  # Default Unix
        if daemon is None:
            if sys.platform == 'darwin' or sys.platform == 'sunos5':
                result = subprocess.run([f'{WAZUH_PATH}/bin/ossec-control', action]).returncode
            else:
                result = subprocess.run(['service', WAZUH_SERVICE, action]).returncode
        else:
            if action == 'restart':
                control_service('stop', daemon=daemon)
                control_service('start', daemon=daemon)
            elif action == 'stop':
                for proc in psutil.process_iter(attrs=['name']):
                    proc.name() == daemon and proc.kill()
            else:
                daemon_path = os.path.join(WAZUH_PATH, 'bin')
                check_call([f'{daemon_path}/{daemon}', '' if not debug_mode else '-d'])
            result = 0

    if result != 0:
        raise ValueError(f"Error when executing {action} in daemon {daemon}. Exit status: {result}")


def get_process(search_name):
    """
    Search process by its name.

    Parameters
    ----------
    search_name : str
        Name of the process to be fetched

    Returns
    -------
    `psutil.Process` or None
        first occurrence of the process object matching the `search_name` or None if no process has been found
    """
    for proc in psutil.process_iter(attrs=['name']):
        if proc.name() == search_name:
            return proc

    return None


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
    time_unit = time[len(time) - 1:]

    if time_unit.isnumeric():
        return timedelta(seconds=int(time))

    time_value = int(time[:len(time) - 1])

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


class SocketController:

    def __init__(self, path, timeout=30, connection_protocol='TCP'):
        """Create a new unix socket or connect to a existing one.

        Parameters
        ----------
        path : str
            Path where the file will be created
        timeout : int
            Socket's timeout, 0 for non-blocking mode
        connection_protocol : str
            Flag that indicates if the connection is TCP (SOCK_STREAM) or UDP (SOCK_DGRAM)

        Raises
        ------
        Exception
            If the socket connection failed
        """
        self.path = path
        if connection_protocol.lower() == 'tcp':
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        elif connection_protocol.lower() == 'udp':
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            wait_for_condition(os.path.exists, args=[self.path], timeout=3)
        else:
            raise TypeError('Invalid connection protocol detected. Valid ones are TCP or UDP')

        try:
            self.sock.settimeout(timeout)
            self.sock.connect(self.path)
        except OSError as e:
            if os.path.exists(path):
                os.unlink(path)
            self.sock.bind(self.path)
            os.chmod(self.path, 0o666)

    def close(self):
        """Close the socket gracefully"""
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def send(self, messages, size=False):
        """Send a list of messages to the socket.

        Parameters
        ----------
        messages : list
            List of messages to be sent
        size : bool
            Flag that indicates if the header of the message includes the size of the message
            (Analysis doesn't need the size, wazuh-db does)

        Returns
        -------
        list
            List of sizes of the sent messages
        """
        output = list()
        for message_ in messages:
            msg_bytes = message_.encode()
            try:
                if size:
                    output.append(self.sock.send(pack("<I", len(msg_bytes)) + msg_bytes))
                else:
                    output.append(self.sock.send(msg_bytes))
            except OSError as e:
                raise e

        return output

    def receive(self, total_messages=1):
        """Receive a specified number of messages from the socket.

        Parameters
        ----------
        total_messages : int
            Total messages to be received

        Returns
        -------
        list
            Socket messages
        """
        output = list()
        for _ in range(0, total_messages):
            try:
                size = unpack("<I", self.sock.recv(4, socket.MSG_WAITALL))[0]
                output.append(self.sock.recv(size, socket.MSG_WAITALL).decode().rstrip('\x00'))
            except OSError:
                try:
                    self.sock.listen(1)
                    conn, addr = self.sock.accept()
                    size = unpack("<I", conn.recv(4, socket.MSG_WAITALL))[0]
                    output.append(conn.recv(size, socket.MSG_WAITALL).decode().rstrip('\x00'))
                except OSError as e:
                    raise e

        return output

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SocketMonitor:

    def __init__(self, path, connection_protocol='TCP', controller=None, socket_timeout=30):
        """Create a new unix socket or connect to a existing one.

        Parameters
        ----------
        path : str
            Path where the file will be created
        connection_protocol : str, optional
            Flag that indicates if the connection is TCP (SOCK_STREAM) or UDP (SOCK_DGRAM)
        socket_timeout : int, optional
            Timeout in seconds to abort a recv operation from the socket

        Raises
        ------
        Exception
            If the socket connection failed
        """
        self._continue = False
        self._abort = False
        self._result = None
        self.timer = None
        self.path = path
        if not controller:
            self.controller = SocketController(path=path, connection_protocol=connection_protocol)
        else:
            self.controller = controller

    def start(self, timeout=-1, callback=_callback_default, accum_results=1):
        """Start the socket monitoring with specified callback.

        Parameters
        ----------
        timeout : int
            Timeout of the operation
        callback : callable
            Callable function that accepts a specified param
        accum_results : int
            Expected number of messages

        Returns
        -------
        list
            Socket messages
        """
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timer = Timer(timeout, self.abort)
                self.timer.start()
            while self._continue:
                if self._abort:
                    self.stop()
                    raise TimeoutError()
                for message in self.controller.receive(accum_results):
                    result = callback(message)
                    if result:
                        self._add_results(result, accum_results)
        return self

    def _add_results(self, result, accum_results):
        if accum_results > 1:
            self._result.append(result)
            accum_results == len(self._result) and self.stop()
        else:
            self._result = result
            self._result and self.stop()

    def result(self):
        """Return the monitored socket messages."""
        return self._result

    def close(self):
        """Close the socket gracefully."""
        self.controller.close()

    def stop(self):
        """Stop the socket monitoring. It can be restarted calling the start method."""
        self._continue = False
        if self.timer:
            self.timer.cancel()
            self.timer.join()
        return self

    def abort(self):
        """Raise a timeout exception if the operation takes more time that the specified timeout."""
        self._abort = True
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def delete_sockets(path=None):
    """Delete a Wazuh socket file or all of them if None is specified

    Parameters
    ----------
    path : str
        Socket path relative to WAZUH_PATH
    """
    try:
        if path is None:
            path = os.path.join(WAZUH_PATH, 'queue', 'ossec')
            for file in os.listdir(path):
                os.remove(os.path.join(path, file))
            os.remove(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
        else:
            os.remove(os.path.join(WAZUH_PATH, path))
    except FileNotFoundError:
        pass


def check_daemon_status(daemon=None, running=True, timeout=10):
    """Check Wazuh daemon status.

    Parameters
    ----------
    daemon : str
        Wazuh daemon to check
    running : bool
        True if the daemon is expected to be running False if it is expected to be stopped
    timeout : int
        Timeout value for the check

    Raises
    ------
    TimeoutError
        If the daemon status is wrong after timeout seconds
    """
    for _ in range(3):
        daemon_status = subprocess.run(['service', 'wazuh-manager', 'status'],
                                       stdout=subprocess.PIPE).stdout.decode()
        if f"{daemon if daemon is not None else ''} {'not' if running is True else 'is'} running" not in daemon_status:
            break
        time.sleep(timeout/3)
    else:
        raise TimeoutError(f"{'wazuh-service' if daemon is None else daemon} "
                           f"{'is not' if running is True else 'is'} running")
