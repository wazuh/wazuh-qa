# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from hashlib import sha1
from json import JSONDecodeError
from stat import ST_ATIME, ST_MTIME
from typing import Sequence, Union, Generator, Any

import pytest
from jsonschema import validate
from wazuh_testing import global_parameters, logger
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.tools.file import generate_string

if sys.platform == 'win32':
    import win32con
    import win32api
    import win32security as win32sec
    import ntsecuritycon as ntc
    import pywintypes
elif sys.platform == 'linux2' or sys.platform == 'linux':
    from jq import jq

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

FIFO = 'fifo'
SYMLINK = 'sym_link'
HARDLINK = 'hard_link'
SOCKET = 'socket'
REGULAR = 'regular'

CHECK_ALL = 'check_all'
CHECK_SUM = 'check_sum'
CHECK_SHA1SUM = 'check_sha1sum'
CHECK_MD5SUM = 'check_md5sum'
CHECK_SHA256SUM = 'check_sha256sum'
CHECK_SIZE = 'check_size'
CHECK_OWNER = 'check_owner'
CHECK_GROUP = 'check_group'
CHECK_PERM = 'check_perm'
CHECK_ATTRS = 'check_attrs'
CHECK_MTIME = 'check_mtime'
CHECK_INODE = 'check_inode'
CHECK_TYPE = 'check_type'

REQUIRED_ATTRIBUTES = {
    CHECK_SHA1SUM: 'hash_sha1',
    CHECK_MD5SUM: 'hash_md5',
    CHECK_SHA256SUM: 'hash_sha256',
    CHECK_SIZE: 'size',
    CHECK_OWNER: ['uid', 'user_name'],
    CHECK_GROUP: ['gid', 'group_name'],
    CHECK_PERM: 'perm',
    CHECK_ATTRS: 'attributes',
    CHECK_MTIME: 'mtime',
    CHECK_INODE: 'inode',
    CHECK_ALL: {CHECK_SHA256SUM, CHECK_SHA1SUM, CHECK_MD5SUM, CHECK_SIZE, CHECK_OWNER,
                CHECK_GROUP, CHECK_PERM, CHECK_ATTRS, CHECK_MTIME, CHECK_INODE},
    CHECK_SUM: {CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_MD5SUM}
}

REQUIRED_REG_KEY_ATTRIBUTES = {
    CHECK_OWNER: ['uid', 'user_name'],
    CHECK_GROUP: ['gid', 'group_name'],
    CHECK_PERM: 'perm',
    CHECK_MTIME: 'mtime',
    CHECK_ALL: {CHECK_OWNER, CHECK_GROUP, CHECK_PERM, CHECK_MTIME}
}

REQUIRED_REG_VALUE_ATTRIBUTES = {
    CHECK_SHA1SUM: 'hash_sha1',
    CHECK_MD5SUM: 'hash_md5',
    CHECK_SHA256SUM: 'hash_sha256',
    CHECK_SIZE: 'size',
    CHECK_TYPE: 'value_type',
    CHECK_ALL: {CHECK_SHA256SUM, CHECK_SHA1SUM, CHECK_MD5SUM, CHECK_SIZE, CHECK_TYPE},
    CHECK_SUM: {CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_MD5SUM}
}

_last_log_line = 0
_os_excluded_from_rt_wd = ['darwin', 'sunos5']
registry_ignore_path = None

if sys.platform == 'win32':
    registry_parser = {
        'HKEY_CLASSES_ROOT': win32con.HKEY_CLASSES_ROOT,
        'HKEY_CURRENT_USER': win32con.HKEY_CURRENT_USER,
        'HKEY_LOCAL_MACHINE': win32con.HKEY_LOCAL_MACHINE,
        'HKEY_USERS': win32con.HKEY_USERS,
        'HKEY_CURRENT_CONFIG': win32con.HKEY_CURRENT_CONFIG
    }

    registry_class_name = {
        win32con.HKEY_CLASSES_ROOT: 'HKEY_CLASSES_ROOT',
        win32con.HKEY_CURRENT_USER: 'HKEY_CURRENT_USER',
        win32con.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE',
        win32con.HKEY_USERS: 'HKEY_USERS',
        win32con.HKEY_CURRENT_CONFIG: 'HKEY_CURRENT_CONFIG'
    }

    registry_value_type = {
        win32con.REG_NONE: 'REG_NONE',
        win32con.REG_SZ: 'REG_SZ',
        win32con.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
        win32con.REG_BINARY: 'REG_BINARY',
        win32con.REG_DWORD: 'REG_DWORD',
        win32con.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
        win32con.REG_LINK: 'REG_LINK',
        win32con.REG_MULTI_SZ: 'REG_MULTI_SZ',
        win32con.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
        win32con.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
        win32con.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
        win32con.REG_QWORD: 'REG_QWORD'
    }

    REG_NONE = win32con.REG_NONE
    REG_SZ = win32con.REG_SZ
    REG_EXPAND_SZ = win32con.REG_EXPAND_SZ
    REG_BINARY = win32con.REG_BINARY
    REG_DWORD = win32con.REG_DWORD
    REG_DWORD_BIG_ENDIAN = win32con.REG_DWORD_BIG_ENDIAN
    REG_LINK = win32con.REG_LINK
    REG_MULTI_SZ = win32con.REG_MULTI_SZ
    REG_RESOURCE_LIST = win32con.REG_RESOURCE_LIST
    REG_FULL_RESOURCE_DESCRIPTOR = win32con.REG_FULL_RESOURCE_DESCRIPTOR
    REG_RESOURCE_REQUIREMENTS_LIST = win32con.REG_RESOURCE_REQUIREMENTS_LIST
    REG_QWORD = win32con.REG_QWORD
    KEY_WOW64_32KEY = win32con.KEY_WOW64_32KEY
    KEY_WOW64_64KEY = win32con.KEY_WOW64_64KEY
    KEY_ALL_ACCESS = win32con.KEY_ALL_ACCESS
    RegOpenKeyEx = win32api.RegOpenKeyEx
    RegCloseKey = win32api.RegCloseKey
else:

    registry_parser = {}
    registry_class_name = {}
    registry_value_type = {}

    KEY_WOW64_32KEY = 0
    KEY_WOW64_64KEY = 0
    REG_NONE = 0
    REG_SZ = 0
    REG_EXPAND_SZ = 0
    REG_BINARY = 0
    REG_DWORD = 0
    REG_DWORD_BIG_ENDIAN = 0
    REG_LINK = 0
    REG_MULTI_SZ = 0
    REG_RESOURCE_LIST = 0
    REG_FULL_RESOURCE_DESCRIPTOR = 0
    REG_RESOURCE_REQUIREMENTS_LIST = 0
    REG_QWORD = 0
    KEY_ALL_ACCESS = 0

    def registry_value_cud():
        pass

    def registry_key_cud():
        pass

    def registry_value_create():
        pass

    def registry_value_update():
        pass

    def registry_value_delete():
        pass

    def create_values_content():
        pass

    def validate_registry_event():
        pass

    RegOpenKeyEx = 0
    RegCloseKey = 0


def validate_event(event, checks=None, mode=None):
    """Check if event is properly formatted according to some checks.

    Args:
        event (dict): represents an event generated by syscheckd.
        checks (:obj:`set`, optional): set of XML CHECK_* options. Default `{CHECK_ALL}`
        mode (:obj:`str`, optional): represents the FIM mode expected for the event to validate.
    """

    def get_required_attributes(check_attributes, result=None):
        result = set() if result is None else result
        for check in check_attributes:
            mapped = REQUIRED_ATTRIBUTES[check]
            if isinstance(mapped, str):
                result |= {mapped}
            elif isinstance(mapped, list):
                result |= set(mapped)
            elif isinstance(mapped, set):
                result |= get_required_attributes(mapped, result=result)
        return result

    json_file = 'syscheck_event_windows.json' if sys.platform == "win32" else 'syscheck_event.json'
    with open(os.path.join(_data_path, json_file), 'r') as f:
        schema = json.load(f)
    validate(schema=schema, instance=event)

    # Check FIM mode
    mode = global_parameters.current_configuration['metadata']['fim_mode'] if mode is None else mode.replace('-', '')
    assert (event['data']['mode']).replace('-', '') == mode, f"The event's FIM mode was '{event['data']['mode']}' \
        but was expected to be '{mode}'"

    # Check attributes
    if checks:
        attributes = event['data']['attributes'].keys() - {'type', 'checksum'}

        required_attributes = get_required_attributes(checks)
        required_attributes -= get_required_attributes({CHECK_GROUP}) if sys.platform == "win32" else {'attributes'}

        intersection = attributes ^ required_attributes
        intersection_debug = "Event attributes are: " + str(attributes)
        intersection_debug += "\nRequired Attributes are: " + str(required_attributes)
        intersection_debug += "\nIntersection is: " + str(intersection)
        assert (intersection == set()), f'Attributes and required_attributes are not the same. ' + intersection_debug

        # Check add file event
        if event['data']['type'] == 'added':
            assert 'old_attributes' not in event['data'] and 'changed_attributes' not in event['data']
        # Check modify file event
        if event['data']['type'] == 'modified':
            assert 'old_attributes' in event['data'] and 'changed_attributes' in event['data']

            old_attributes = event['data']['old_attributes'].keys() - {'type', 'checksum'}
            old_intersection = old_attributes ^ required_attributes
            old_intersection_debug = "Event attributes are: " + str(old_attributes)
            old_intersection_debug += "\nRequired Attributes are: " + str(required_attributes)
            old_intersection_debug += "\nIntersection is: " + str(old_intersection)
            assert (old_intersection == set()), (f'Old_attributes and required_attributes are not the same. ' +
                                                 old_intersection_debug)


def validate_registry_key_event(event, checks=None, mode=None):
    """Check if event is properly formatted according to some checks.

    Args:
        event (dict): represents an event generated by syscheckd.
        checks (:obj:`set`, optional): set of XML CHECK_* options. Default `{CHECK_ALL}`
        mode (:obj:`str`, optional): represents the FIM mode expected for the event to validate.
    """

    def get_required_attributes(check_attributes, result=None):
        result = set() if result is None else result
        for check in check_attributes:
            mapped = REQUIRED_REG_KEY_ATTRIBUTES[check]

            if isinstance(mapped, str):
                result |= {mapped}
            elif isinstance(mapped, list):
                result |= set(mapped)
            elif isinstance(mapped, set):
                result |= get_required_attributes(mapped, result=result)

        return result

    json_file = 'syscheck_event_windows.json' if sys.platform == "win32" else 'syscheck_event.json'
    with open(os.path.join(_data_path, json_file), 'r') as f:
        schema = json.load(f)

    validate(schema=schema, instance=event)

    # Check FIM mode
    mode = global_parameters.current_configuration['metadata']['fim_mode'] if mode is None else mode.replace('-', '')
    assert (event['data']['mode']).replace('-', '') == mode, f"The event's FIM mode was '{event['data']['mode']}' \
        but was expected to be '{mode}'"

    # Check attributes
    if checks:
        attributes = event['data']['attributes'].keys() - {'type', 'checksum'}

        required_attributes = get_required_attributes(checks)

        intersection = attributes ^ required_attributes
        intersection_debug = "Event attributes are: " + str(attributes)
        intersection_debug += "\nRequired Attributes are: " + str(required_attributes)
        intersection_debug += "\nIntersection is: " + str(intersection)

        assert (intersection == set()), f'Attributes and required_attributes are not the same. ' + intersection_debug

        # Check add file event
        if event['data']['type'] == 'added':
            assert 'old_attributes' not in event['data'] and 'changed_attributes' not in event['data']

        # Check modify file event
        if event['data']['type'] == 'modified':
            assert 'old_attributes' in event['data'] and 'changed_attributes' in event['data']

            old_attributes = event['data']['old_attributes'].keys() - {'type', 'checksum'}
            old_intersection = old_attributes ^ required_attributes
            old_intersection_debug = "Event attributes are: " + str(old_attributes)
            old_intersection_debug += "\nRequired Attributes are: " + str(required_attributes)
            old_intersection_debug += "\nIntersection is: " + str(old_intersection)

            assert (old_intersection == set()), (f'Old_attributes and required_attributes are not the same. ' +
                                                 old_intersection_debug)


def validate_registry_value_event(event, checks=None, mode=None):
    """Check if event is properly formatted according to some checks.

    Args:
        event (dict): represents an event generated by syscheckd.
        checks (:obj:`set`, optional): set of XML CHECK_* options. Default `{CHECK_ALL}`
        mode (:obj:`str`, optional): represents the FIM mode expected for the event to validate.
    """

    def get_required_attributes(check_attributes, result=None):
        result = set() if result is None else result
        for check in check_attributes:
            mapped = REQUIRED_REG_VALUE_ATTRIBUTES[check]

            if isinstance(mapped, str):
                result |= {mapped}
            elif isinstance(mapped, list):
                result |= set(mapped)
            elif isinstance(mapped, set):
                result |= get_required_attributes(mapped, result=result)

        return result

    json_file = 'syscheck_event_windows.json' if sys.platform == "win32" else 'syscheck_event.json'
    with open(os.path.join(_data_path, json_file), 'r') as f:
        schema = json.load(f)

    validate(schema=schema, instance=event)

    # Check FIM mode
    mode = global_parameters.current_configuration['metadata']['fim_mode'] if mode is None else mode.replace('-', '')
    assert (event['data']['mode']).replace('-', '') == mode, f"The event's FIM mode was '{event['data']['mode']}' \
        but was expected to be '{mode}'"

    # Check attributes
    if checks:
        attributes = event['data']['attributes'].keys() - {'type', 'checksum'}

        required_attributes = get_required_attributes(checks)

        intersection = attributes ^ required_attributes
        intersection_debug = "Event attributes are: " + str(attributes)
        intersection_debug += "\nRequired Attributes are: " + str(required_attributes)
        intersection_debug += "\nIntersection is: " + str(intersection)

        assert (intersection == set()), f'Attributes and required_attributes are not the same. ' + intersection_debug

        # Check add file event
        if event['data']['type'] == 'added':
            assert 'old_attributes' not in event['data'] and 'changed_attributes' not in event['data']

        # Check modify file event
        if event['data']['type'] == 'modified':
            assert 'old_attributes' in event['data'] and 'changed_attributes' in event['data']

            old_attributes = event['data']['old_attributes'].keys() - {'type', 'checksum'}
            old_intersection = old_attributes ^ required_attributes
            old_intersection_debug = "Event attributes are: " + str(old_attributes)
            old_intersection_debug += "\nRequired Attributes are: " + str(required_attributes)
            old_intersection_debug += "\nIntersection is: " + str(old_intersection)

            assert (old_intersection == set()), (f'Old_attributes and required_attributes are not the same. ' +
                                                 old_intersection_debug)


def is_fim_scan_ended():
    """Check if a FIM scan has ended or not

    Returns:
        int: returns the line number where the scan has ended or -1 for any other case.
    """
    message = 'File integrity monitoring scan ended.'
    line_number = 0
    with open(LOG_FILE_PATH, 'r') as f:
        for line in f:
            line_number += 1
            if line_number > _last_log_line:  # Ignore if has not reached from_line
                if message in line:
                    globals()['_last_log_line'] = line_number
                    return line_number
    return -1


def create_file(type_, path, name, **kwargs):
    """Create a file in a given path. The path will be created in case it does not exists.

    Args:
        type_ (str): defined constant that specifies the type. It can be: FIFO, SYSLINK, Socket or REGULAR.
        path (str): path where the file will be created.
        name (str): file name.
        **kwargs: Arbitrary keyword arguments.

    Keyword Args:
            **content (str): content of the created regular file.
            **target (str): path where the link will be pointing to.

    Raises:
        ValueError: if `target` is missing for SYMLINK or HARDINK.
    """

    try:
        logger.info("Creating file " + str(os.path.join(path, name)) + " of " + str(type_) + " type")
        os.makedirs(path, exist_ok=True, mode=0o777)
        if type_ != REGULAR:
            try:
                kwargs.pop('content')
            except KeyError:
                pass
        if type_ in (SYMLINK, HARDLINK) and 'target' not in kwargs:
            raise ValueError(f"'target' param is mandatory for type {type_}")
        getattr(sys.modules[__name__], f'_create_{type_}')(path, name, **kwargs)
    except OSError:
        logger.info("File could not be created.")
        pytest.skip("OS does not allow creating this file.")


def create_registry(key, subkey, arch):
    """Create a registry given the key and the subkey. The registry is opened if it already exists.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).

    Returns:
         str: the key handle of the new/opened key.
    """

    if sys.platform == 'win32':
        try:
            logger.info("Creating registry key " + str(os.path.join(registry_class_name[key], subkey)))

            key = win32api.RegCreateKeyEx(key, subkey, win32con.KEY_ALL_ACCESS | arch)

            return key[0]  # Ignore the flag that RegCreateKeyEx returns
        except OSError as e:
            logger.warning(f"Registry could not be created: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry could not be created: {e}")


def _create_fifo(path, name):
    """Create a FIFO file.

    Args:
        path (str): path where the file will be created.
        name (str): file name.

    Raises:
        OSError: if `mkfifo` fails.
    """
    fifo_path = os.path.join(path, name)
    try:
        os.mkfifo(fifo_path)
    except OSError:
        raise


def _create_sym_link(path, name, target):
    """Create a symbolic link.

    Args:
        path (str): path where the symbolic link will be created.
        name (str): file name.
        target (str): path where the symbolic link will be pointing to.

    Raises:
        OSError: if `symlink` fails.
    """
    symlink_path = os.path.join(path, name)
    try:
        os.symlink(target, symlink_path)
    except OSError:
        raise


def _create_hard_link(path, name, target):
    """Create a hard link.

    Args:
        path (str): path where the hard link will be created.
        name (str): file name.
        target (str): path where the hard link will be pointing to.

    Raises:
        OSError: if `link` fails.
    """
    link_path = os.path.join(path, name)
    try:
        os.link(target, link_path)
    except OSError:
        raise


def _create_socket(path, name):
    """Create a Socket file.

    Args:
        path (str): path where the socket will be created.
        name (str): file name.

    Raises:
        OSError: if `unlink` fails.
    """
    socket_path = os.path.join(path, name)
    try:
        os.unlink(socket_path)
    except OSError:
        if os.path.exists(socket_path):
            raise
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)


def _create_regular(path, name, content=''):
    """Create a regular file.

    Args:
        path (str): path where the regular file will be created.
        name (str): file name.
        content (str, optional): content of the created file. Default `''`
    """
    regular_path = os.path.join(path, name)
    mode = 'wb' if isinstance(content, bytes) else 'w'

    with open(regular_path, mode) as f:
        f.write(content)


def _create_regular_windows(path, name, content=''):
    """Create a regular file in Windows

    Args:
        path (str): path where the regular file will be created.
        name (str): file name.
        content (str, optional): content of the created file. Default `''`
    """
    regular_path = os.path.join(path, name)
    os.popen("echo " + content + " > " + regular_path + f" runas /user:{os.getlogin()}")


def delete_file(path, name):
    """Delete a regular file.

    Args:
        path (str): path to the file to be deleted.
        name (str): name of the file to be deleted.
    """
    logger.info(f"Removing file {str(os.path.join(path, name))}")
    regular_path = os.path.join(path, name)
    if os.path.exists(regular_path):
        os.remove(regular_path)


def delete_registry(key, subkey, arch):
    """Delete a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """
    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == KEY_WOW64_64KEY else '[x32]'
        logger.info(f"Removing registry key {print_arch}{str(os.path.join(registry_class_name[key], subkey))}")

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)
            win32api.RegDeleteTree(key_h, None)
            win32api.RegDeleteKeyEx(key, subkey, samDesired=arch)
        except OSError as e:
            logger.warning(f"Couldn't remove registry key {str(os.path.join(registry_class_name[key], subkey))}: {e}")
        except pywintypes.error as e:
            logger.warning(f"Couldn't remove registry key {str(os.path.join(registry_class_name[key], subkey))}: {e}")


def delete_registry_value(key_h, value_name):
    """Delete a registry value from a registry key.

    Args:
        key_h (pyHKEY): the key handle of the registry.
        value_name (str): the value to be deleted.
    """
    if sys.platform == 'win32':
        logger.info(f"Removing registry value {value_name}.")

        try:
            win32api.RegDeleteValue(key_h, value_name)
        except OSError as e:
            logger.warning(f"Couldn't remove registry value {value_name}: {e}")
        except pywintypes.error as e:
            logger.warning(f"Couldn't remove registry value {value_name}: {e}")


def modify_registry_value(key_h, value_name, type, value):
    """
    Modify the content of a registry. If the value doesn't not exists, it will be created.

    Args:
        key_h (pyHKEY): the key handle of the registry.
        value_name (str): the value to be set.
        type (int): type of the value.
        value (str): the content that will be written to the registry value.
    """
    if sys.platform == 'win32':
        try:
            logger.info(f"Modifying value '{value_name}' of type {registry_value_type[type]} and value '{value}'")
            win32api.RegSetValueEx(key_h, value_name, 0, type, value)
        except OSError as e:
            logger.warning(f"Could not modify registry value content: {e}")
        except pywintypes.error as e:
            logger.warning(f"Could not modify registry value content: {e}")


def modify_key_perms(key, subkey, arch, user):
    """
    Modify the permissions (ACL) of a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (str): architecture of the system.
        user (PySID): user that is going to be used for the modification.
    """
    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == KEY_WOW64_64KEY else '[x32]'
        logger.info(f"- Changing permissions of {print_arch}{os.path.join(registry_class_name[key], subkey)}")

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)
            sd = win32api.RegGetKeySecurity(key_h, win32con.DACL_SECURITY_INFORMATION)
            acl = sd.GetSecurityDescriptorDacl()
            acl.AddAccessAllowedAce(ntc.GENERIC_ALL, user)
            sd.SetDacl(True, acl, False)

            win32api.RegSetKeySecurity(key_h, win32con.DACL_SECURITY_INFORMATION, sd)
        except OSError as e:
            logger.warning(f"Registry permissions could not be modified: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry permissions could not be modified: {e}")


def modify_registry_key_mtime(key, subkey, arch):
    """Modify the modification time of a registry key.

    Args:
        key (pyHKEY): the key handle of the registry.
        subkey (str): the subkey (name) of the registry.
        arch (str): architecture of the system.
    """

    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == KEY_WOW64_64KEY else '[x32]'
        logger.info(f"- Changing mtime of {print_arch}{os.path.join(registry_class_name[key], subkey)}")

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)

            modify_registry_value(key_h, "dummy_value", win32con.REG_SZ, "this is a dummy value")
            time.sleep(2)
            delete_registry_value(key_h, "dummy_value")

            win32api.RegCloseKey(key_h)
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS)
        except OSError as e:
            logger.warning(f"Registry mtime could not be modified: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry mtime could not be modified: {e}")


def modify_registry_owner(key, subkey, arch, user):
    """Modify the owner of a registry key.

    Arch:
        key (pyHKEY): the key handle of the registry.
        subkey (str): the subkey (name) of the registry.
        arch (str): architecture of the system.
        user (pySID): identifier of the user (pySID)

    Returns:
        str: key of the registry.
    """
    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == KEY_WOW64_64KEY else '[x32]'
        logger.info(f"- Changing owner of {print_arch}{os.path.join(registry_class_name[key], subkey)}")

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)
            desc = win32api.RegGetKeySecurity(key_h,
                                              win32sec.DACL_SECURITY_INFORMATION | win32sec.OWNER_SECURITY_INFORMATION)
            desc.SetSecurityDescriptorOwner(user, 0)

            win32api.RegSetKeySecurity(key_h, win32sec.OWNER_SECURITY_INFORMATION | win32sec.DACL_SECURITY_INFORMATION,
                                       desc)

            return key_h
        except OSError as e:
            logger.warning(f"Registry owner could not be modified: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry owner could not be modified: {e}")


def modify_registry(key, subkey, arch):
    """Modify a registry key.

    Args:
        key (pyHKEY): the key handle of the registry.
        subkey (str): the subkey (name) of the registry.
        arch (str): architecture of the system.
    """
    print_arch = '[x64]' if arch == KEY_WOW64_64KEY else '[x32]'
    logger.info(f"Modifying registry key {print_arch}{os.path.join(registry_class_name[key], subkey)}")

    modify_key_perms(key, subkey, arch, win32sec.LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")[0])
    modify_registry_owner(key, subkey, arch, win32sec.LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")[0])
    modify_registry_key_mtime(key, subkey, arch)


def rename_registry(key, subkey_path, src_name, arch, dst_name):
    """Rename a registry key.

    Args:
        key (int): the key of the registry (HKEY_* constants).
        subkey_path (str): the path where the subkey that is going to be renamed is.
        src_name (str): name of the key that is going to be renamed
        arch (int): architecture of the system.
        dst_name (str): name of the renamed key
    """
    if sys.platform == 'win32':
        logger.info(f"- Renaming registry {src_name} to {dst_name}")

        try:
            source_key = os.path.join(subkey_path, src_name)
            destination_key = os.path.join(subkey_path, dst_name)

            src_key_h = win32api.RegOpenKey(key, source_key, 0, win32con.KEY_ALL_ACCESS | arch)
            dst_key_h = create_registry(key, destination_key, arch)

            win32api.RegCopyTree(src_key_h, None, dst_key_h)

            delete_registry(key, source_key, arch)
        except OSError as e:
            logger.warning(f"Registry could not be renamed: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry could not be renamed: {e}")


def modify_file_content(path, name, new_content=None, is_binary=False):
    """Modify the content of a file.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
        new_content (str, optional): new content to append to the file. Previous content will remain. Defaults `None`
        is_binary (boolean, optional): True if the file's content is in binary format. False otherwise. Defaults `False`
    """
    path_to_file = os.path.join(path, name)
    logger.info("- Changing content of " + str(path_to_file))
    content = "1234567890qwertyu" if new_content is None else new_content
    with open(path_to_file, 'ab' if is_binary else 'a') as f:
        f.write(content.encode() if is_binary else content)


def modify_file_mtime(path, name):
    """Change the modification time of a file.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    path_to_file = os.path.join(path, name)
    logger.info("- Changing mtime of " + str(path_to_file))
    stat = os.stat(path_to_file)
    access_time = stat[ST_ATIME]
    modification_time = stat[ST_MTIME]
    modification_time = modification_time + 1000
    os.utime(path_to_file, (access_time, modification_time))


def modify_file_owner(path, name):
    """Change the owner of a file. The new owner will be '1'.

    On Windows, uid will always be 0.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """

    def modify_file_owner_windows():
        cmd = f"takeown /S 127.0.0.1 /U {os.getlogin()} /F " + path_to_file
        subprocess.call(cmd)

    def modify_file_owner_unix():
        os.chown(path_to_file, 1, -1)

    path_to_file = os.path.join(path, name)
    logger.info("- Changing owner of " + str(path_to_file))

    if sys.platform == 'win32':
        modify_file_owner_windows()
    else:
        modify_file_owner_unix()


def modify_file_group(path, name):
    """Change the group of a file. The new group will be '1'.

    Available for UNIX. On Windows, gid will always be 0 and the group name will be blank.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    if sys.platform == 'win32':
        return

    path_to_file = os.path.join(path, name)
    logger.info("- Changing group of " + str(path_to_file))
    os.chown(path_to_file, -1, 1)


def modify_file_permission(path, name):
    """Change the permission of a file.

    On UNIX the new permissions will be '666'.
    On Windows, a list of denied and allowed permissions will be given for each user or group since version 3.8.0.
    Only works on NTFS partitions on Windows systems.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """

    def modify_file_permission_windows():
        user, _, _ = win32sec.LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")
        sd = win32sec.GetFileSecurity(path_to_file, win32sec.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32sec.ACL_REVISION, ntc.FILE_ALL_ACCESS, user)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32sec.SetFileSecurity(path_to_file, win32sec.DACL_SECURITY_INFORMATION, sd)

    def modify_file_permission_unix():
        os.chmod(path_to_file, 0o666)

    path_to_file = os.path.join(path, name)

    logger.info("- Changing permission of " + str(path_to_file))

    if sys.platform == 'win32':
        modify_file_permission_windows()
    else:
        modify_file_permission_unix()


def modify_file_inode(path, name):
    """Change the inode of a file for Linux.

    On Windows, this function does nothing.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    if sys.platform == 'win32':
        return

    logger.info("- Changing inode of " + str(os.path.join(path, name)))
    inode_file = 'inodetmp'
    path_to_file = os.path.join(path, name)

    shutil.copy2(path_to_file, os.path.join(tempfile.gettempdir(), inode_file))
    shutil.move(os.path.join(tempfile.gettempdir(), inode_file), path_to_file)


def modify_file_win_attributes(path, name):
    """Change the attribute of a file in Windows

    On other OS, this function does nothing.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    if sys.platform != 'win32':
        return

    logger.info("- Changing win attributes of " + str(os.path.join(path, name)))
    path_to_file = os.path.join(path, name)
    win32api.SetFileAttributes(path_to_file, win32con.FILE_ATTRIBUTE_HIDDEN)


def modify_file(path, name, new_content=None, is_binary=False):
    """Modify a Regular file.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
        new_content (str, optional): new content to add to the file. Defaults `None`.
        is_binary: (boolean, optional): True if the file is binary. False otherwise. Defaults `False`
    """
    logger.info("Modifying file " + str(os.path.join(path, name)))
    modify_file_inode(path, name)
    modify_file_content(path, name, new_content, is_binary)
    modify_file_mtime(path, name)
    modify_file_owner(path, name)
    modify_file_group(path, name)
    modify_file_permission(path, name)
    modify_file_win_attributes(path, name)


def change_internal_options(param, value, opt_path=None, value_regex='[0-9]*'):
    """Change the value of a given parameter in local_internal_options.

    Args:
        param (str): parameter to change.
        value (obj): new value.
        opt_path (str, optional): local_internal_options.conf path. Defaults `None`
        value_regex (str, optional): regex to match value in local_internal_options.conf. Default '[0-9]*'
    """
    if opt_path is None:
        local_conf_path = os.path.join(WAZUH_PATH, 'local_internal_options.conf') if sys.platform == 'win32' else \
            os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    else:
        local_conf_path = opt_path

    add_pattern = True
    with open(local_conf_path, "r") as sources:
        lines = sources.readlines()

    with open(local_conf_path, "w") as sources:
        for line in lines:
            sources.write(
                re.sub(f'{param}={value_regex}', f'{param}={value}', line))
            if param in line:
                add_pattern = False

    if add_pattern:
        with open(local_conf_path, "a") as sources:
            sources.write(f'\n\n{param}={value}')


def change_conf_param(param, value):
    """Change the value of a given parameter in ossec.conf.

    Args:
        param (str): parameter to change.
        value (obj): new value.
    """
    conf_path = os.path.join(WAZUH_PATH, 'ossec.conf') if sys.platform == 'win32' else \
        os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')

    with open(conf_path, "r") as sources:
        lines = sources.readlines()

    with open(conf_path, "w") as sources:
        for line in lines:
            sources.write(
                re.sub(f'<{param}>.*</{param}>', f'<{param}>{value}</{param}>', line))


def callback_detect_end_scan(line):
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_end':
            return True
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_scan_start(line):
    """
    Detect the start of a scheduled scan or initial scan.
    """
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_start':
            return True
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_get_scan_timestap(line):
    """
    Get the timestamp for the end of the initial scan or a scheduled scan
    """
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None
    try:
        if json.loads(match.group(1))['type'] == 'scan_end':
            return json.loads(match.group(1))['data']['timestamp']
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_event(line):
    """
    Detect an 'event' type FIM log.
    """
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event':
            return json_event
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_modified_event(line):
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event' and json_event['data']['type'] == 'modified':
            return json_event
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_delete_event(line):
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event' and json_event['data']['type'] == 'deleted':
            return json_event
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_modified_event_with_inode_mtime(line):
    msg = r'.*Sending FIM event: (.+)$'
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event' and json_event['data']['type'] == 'modified':
            # If 'changed_attributes' are not exactly 'inode' and 'mtime', symmetric_difference
            # will return a non-empty set, returning the event.
            if {'inode', 'mtime'}.symmetric_difference(set(json_event['data']['changed_attributes'])):
                return json_event
    except (JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_integrity_event(line):
    match = re.match(r'.*Sending integrity control message: (.+)$', line)
    if match:
        return json.loads(match.group(1))
    return None


def callback_detect_integrity_state(line):
    event = callback_detect_integrity_event(line)
    if event:
        if event['type'] == 'state':
            return event
    return None


def callback_start_synchronization(line):
    """ Callback that detects if a line contains the FIM sync module has started.

    Args:
        line (String): string line to be checked by callback in File_Monitor.
    """
    if 'FIM sync module started' in line:
        return line
    return None


def callback_detect_synchronization(line):
    """ Callback that detects if a line contains a FIM sync has started.

    Args:
        line (String): string line to be checked by callback in File_Monitor.
    """
    if 'Executing FIM sync' in line:
        return line
    return None


def callback_detect_anything(line):
    match = re.match(r'.*', line)
    if match:
        return line
    return None


def callback_ignore(line):
    match = re.match(r".*Ignoring '.*?' '(.*?)' due to( sregex)? '.*?'", line)
    if match:
        return match.group(1)
    return None


def callback_restricted(line):
    match = re.match(r".*Ignoring entry '(.*?)' due to restriction '.*?'", line)
    if match:
        return match.group(1)
    return None


def callback_audit_health_check(line):
    if 'Whodata health-check: Success.' in line:
        return True
    return None


def callback_audit_added_rule(line):
    match = re.match(r'.*Added audit rule for monitoring directory: \'(.+)\'', line)
    if match:
        return match.group(1)
    return None


def callback_audit_rules_manipulation(line):
    if 'Detected Audit rules manipulation' in line:
        return True
    return None


def callback_audit_removed_rule(line):
    match = re.match(r'.* Audit rule removed.', line)
    if match:
        return True
    return None


def callback_audit_deleting_rule(line):
    match = re.match(r'.*Deleting Audit rules\.', line)
    if match:
        return True
    return None


def callback_audit_connection(line):
    if '(6030): Audit: connected' in line:
        return True
    return None


def callback_audit_connection_close(line):
    match = re.match(r'.*Audit: connection closed.', line)
    if match:
        return True
    return None


def callback_audit_loaded_rule(line):
    match = re.match(r'.*Audit rule loaded: -w (.+) -p', line)
    if match:
        return match.group(1)
    return None


def callback_end_audit_reload_rules(line):
    match = re.match(r'.*Audit rules reloaded\. Rules loaded: (.+)', line)
    if match:
        return match.group(1)
    return None


def callback_audit_event_too_long(line):
    if 'Caching Audit message: event too long' in line:
        return True
    return None


def callback_audit_reloading_rules(line):
    match = re.match(r'.*Reloading Audit rules', line)
    if match:
        return True


def callback_audit_reloaded_rule(line):
    match = re.match(r'.*Already added audit rule for monitoring directory: \'(.+)\'', line)
    if match:
        return match.group(1)
    return None


def callback_audit_key(line):
    if 'Match audit_key' in line and 'key="wazuh_hc"' not in line and 'key="wazuh_fim"' not in line:
        return line
    return None


def callback_audit_unable_dir(line):
    match = re.match(r'.*Unable to add audit rule for \'(.+)\'', line)
    if match:
        return match.group(1)
    return None


def callback_realtime_added_directory(line):
    match = re.match(r'.*Directory added for real time monitoring: \'(.+)\'', line)
    if match:
        return match.group(1)
    return None


def callback_configuration_error(line):
    match = re.match(r'.* \(\d+\): Configuration error at', line)
    if match:
        return True
    return None


def callback_symlink_scan_ended(line):
    if 'Links check finalized.' in line:
        return True
    else:
        return None


def callback_integrity_message(line):
    if callback_detect_integrity_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))


def callback_event_message(line):
    if callback_detect_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))
        return None


def callback_empty_directories(line):
    match = re.match(r'.*DEBUG: \(6338\): Empty directories tag found in the configuration.', line)

    if match:
        return True
    else:
        return None


def callback_real_time_whodata_started(line):
    if 'File integrity monitoring real-time Whodata engine started' in line:
        return True


def callback_non_existing_monitored_dir(line):
    if 'Unable to add directory to real time monitoring:' in line or 'does not exist. Monitoring discarded.' in line:
        return True


def callback_num_inotify_watches(line):
    match = re.match(r'.*Folders monitored with real-time engine: (\d+)', line)

    if match:
        return match.group(1)


def callback_file_size_limit_reached(line):
    match = re.match(r'.*File \'(.*)\' is too big for configured maximum size to perform diff operation\.', line)

    if match:
        return match.group(1)


def callback_disk_quota_limit_reached(line):
    match = re.match(r'.*The (.*) of the file size \'(.*)\' exceeds the disk_quota.*', line)

    if match:
        return match.group(2)


def callback_disk_quota_default(line):
    match = re.match(r'.*Maximum disk quota size limit configured to \'(\d+) KB\'.*', line)

    if match:
        return match.group(1)


def callback_deleted_diff_folder(line):
    match = re.match(r'.*Folder \'(.*)\' has been deleted.*', line)

    if match:
        return match.group(1)


def callback_non_existing_monitored_registry(line):
    if 'Registry key does not exists' in line:
        return True


def callback_registry_count_entries(line):
    match = re.match(r".*Fim registry entries: (\d+)", line)

    if match:
        return match.group(1)


def callback_key_event(line):
    event = callback_detect_event(line)

    if (event is None or event['data']['attributes']['type'] != 'registry_key' or
            event['data']['path'] == registry_ignore_path):
        return None

    return event


def callback_value_event(line):
    event = callback_detect_event(line)

    if event is None or event['data']['attributes']['type'] != 'registry_value':
        return None

    return event


def callback_detect_max_files_per_second(line):
    msg = r'.*Maximum number of files read per second reached, sleeping\.'
    match = re.match(msg, line)

    return match is not None


def callback_detect_end_runtime_wildcards(line):
    match = re.match(r".*Configuration wildcards update finalize\.", line)
    return match is not None


def callback_ignore_realtime_flag(line):
    match = re.match(r".*Ignoring flag for real time monitoring on directory: (.+)$", line)
    if match:
        return True


def check_time_travel(time_travel: bool, interval: timedelta = timedelta(hours=13), monitor: FileMonitor = None,
                      timeout=global_parameters.default_timeout):
    """Checks if the conditions for changing the current time and date are met and call to the specific function
       depending on those conditions.

    Optionally, a monitor may be used to check if a scheduled scan has been performed.

    This function is specially useful to deal with scheduled scans that are triggered on a time interval basis.

    Args:
        time_travel (boolean): True if we need to update time. False otherwise.
        interval (timedelta, optional): time interval that will be added to system clock. Default: 13 hours.
        monitor (FileMonitor, optional): if passed, after changing system clock it will check for the end of the
            scheduled scan. The `monitor` will not consume any log line. Default `None`.
        timeout (int, optional): If a monitor is provided, this parameter sets how log to wait for the end of scan.
    Raises
        TimeoutError: if `monitor` is not `None` and the scan has not ended in the
            default timeout specified in `global_parameters`.
    """

    if 'fim_mode' in global_parameters.current_configuration['metadata'].keys():
        mode = global_parameters.current_configuration['metadata']['fim_mode']
        if mode != 'scheduled' or mode not in global_parameters.fim_mode:
            return

    if time_travel:
        before = str(datetime.now())
        TimeMachine.travel_to_future(interval)
        logger.info(f"Changing the system clock from {before} to {str(datetime.now())}")

        if monitor:
            monitor.start(timeout=timeout, callback=callback_detect_end_scan,
                          update_position=False,
                          error_message=f"End of scheduled scan not detected after {timeout} seconds")


def callback_configuration_warning(line):
    match = re.match(r'.*WARNING: \(\d+\): Invalid value for element', line)
    if match:
        return True
    return None


def callback_warn_max_dir_monitored(line):
    match = re.match(r'.*Maximum number of directories to be monitored in the same tag reached \(\d+\) '
                     r'Excess are discarded: \'(.+)\'', line)
    if match:
        return match.group(1)
    return None


def callback_max_registry_monitored(line):
    match = re.match(r'.*Maximum number of registries to be monitored in the same tag reached \(\d+\) '
                     r'Excess are discarded: \'(.+)\'', line)

    if match:
        return match.group(1)


def callback_delete_watch(line):
    if sys.platform == 'win32':
        match = re.match(r".*Realtime watch deleted for '(\S+)'", line)
    else:
        match = re.match(r".*Inotify watch deleted for '(\S+)'", line)

    if match:
        return match.group(1)


def wait_for_scheduled_scan(wait_for_scan=False, interval: timedelta = timedelta(seconds=20),
                            monitor: FileMonitor = None, timeout=global_parameters.default_timeout):
    """Checks if the conditions for waiting for a new scheduled scan.

    Optionally, a monitor may be used to check if a scheduled scan has been performed.

    This function is specially useful to deal with scheduled scans that are triggered on a time interval basis.

    Args:
        wait_scan (boolean): True if we need to update time. False otherwise.
        interval (timedelta, optional): time interval that will be waited for the scheduled scan to start.
            Default: 20 seconds.
        monitor (FileMonitor, optional): if passed, after changing system clock it will check for the end of the
            scheduled scan. The `monitor` will not consume any log line. Default `None`.
        timeout (int, optional): If a monitor is provided, this parameter sets how long to wait for the end of scan.
    Raises
        TimeoutError: if `monitor` is not `None` and the scan has not ended in the
            default timeout specified in `global_parameters`.
    """

    if 'fim_mode' in global_parameters.current_configuration['metadata'].keys():
        mode = global_parameters.current_configuration['metadata']['fim_mode']
        if mode != 'scheduled' or mode not in global_parameters.fim_mode:
            return

    if wait_for_scan:
        logger.info(f"waiting for scheduled scan to start for {interval} seconds")
        time.sleep(interval)
        if monitor:
            monitor.start(timeout=timeout, callback=callback_detect_end_scan,
                          update_position=False,
                          error_message=f"End of scheduled scan not detected after {timeout} seconds")


if sys.platform == 'win32':
    class RegistryEventChecker:
        """Utility to allow fetch events and validate them."""

        def __init__(self, log_monitor, registry_key, registry_dict=None, options=None, custom_validator=None,
                     encoding=None, callback=callback_detect_event, is_value=False):
            self.log_monitor = log_monitor
            self.registry_key = registry_key
            global registry_ignore_path
            registry_ignore_path = registry_key
            self.registry_dict = registry_dict
            self.custom_validator = custom_validator
            self.options = options
            self.encoding = encoding
            self.events = None
            self.callback = callback
            self.is_value = is_value

        def __del__(self):
            global registry_ignore_path
            registry_ignore_path = None

        def fetch_and_check(self, event_type, min_timeout=1, triggers_event=True, extra_timeout=0):
            """Call 'fetch_events', 'fetch_key_events' and 'check_events', depending on the type of event expected.

            Args:
                event_type (str): Expected type of the raised event {'added', 'modified', 'deleted'}.
                min_timeout (int, optional): seconds to wait until an event is raised when trying to fetch. Defaults `1`
                triggers_event (boolean, optional): True if the event should be raised. False otherwise. Defaults `True`
                extra_timeout (int, optional): Additional time to wait after the min_timeout
            """
            assert event_type in ['added', 'modified', 'deleted'], f'Incorrect event type: {event_type}'

            num_elems = len(self.registry_dict)

            error_msg = "TimeoutError was raised because "
            error_msg += str(num_elems) if num_elems > 1 else "a single"
            error_msg += " '" + str(event_type) + "' "
            error_msg += "events were " if num_elems > 1 else "event was "
            error_msg += "expected for " + str(self._get_elem_list())
            error_msg += " but were not detected." if num_elems > 1 else " but was not detected."

            key_error_msg = f"TimeoutError was raised because 1 event was expected for {self.registry_key} "
            key_error_msg += 'but was not detected.'

            if event_type == 'modified' or self.is_value:
                self.events = self.fetch_events(min_timeout, triggers_event, extra_timeout, error_message=error_msg)
                self.check_events(event_type)
            elif event_type == 'added':
                self.events = self.fetch_events(min_timeout, triggers_event, extra_timeout, error_message=error_msg)
                self.check_events(event_type)
            elif event_type == 'deleted':
                self.events = self.fetch_events(min_timeout, triggers_event, extra_timeout, error_message=error_msg)
                self.check_events(event_type)

        def fetch_events(self, min_timeout=1, triggers_event=True, extra_timeout=0, error_message=''):
            timeout_per_registry_estimation = 0.01
            try:
                result = self.log_monitor.start(timeout=max((len(self.registry_dict)) * timeout_per_registry_estimation,
                                                            min_timeout),
                                                callback=self.callback, accum_results=len(self.registry_dict),
                                                timeout_extra=extra_timeout, encoding=self.encoding,
                                                error_message=error_message).result()

                assert triggers_event, 'No events should be detected.'
                return result if isinstance(result, list) else [result]
            except TimeoutError:
                if triggers_event:
                    raise
                logger.info("TimeoutError was expected and correctly caught.")

        def check_events(self, event_type, mode=None):
            """Check and validate all events in the 'events' list.

            Args:
                event_type (str): Expected type of the raised event {'added', 'modified', 'deleted'}.
                mode (str): expected mode of the raised event.
            """

            def validate_checkers_per_event(events, options, mode):
                """Check if each event is properly formatted according to some checks.

                Args:
                    events (list): event list to be checked.
                    options (set): set of XML CHECK_* options. Default `{CHECK_ALL}`
                    mode (str): represents the FIM mode expected for the event to validate.
                """
                for ev in events:
                    if self.is_value:
                        validate_registry_value_event(ev, options, mode)
                    else:
                        validate_registry_key_event(ev, options, mode)

            def check_events_type(events, ev_type, reg_list=['testkey0']):
                event_types = Counter(filter_events(events, ".[].data.type"))

                assert (event_types[ev_type] == len(reg_list)
                        ), f'Non expected number of events. {event_types[ev_type]} != {len(reg_list)}'

            def check_events_key_path(events, registry_key, reg_list=['testkey0'], mode=None):
                mode = global_parameters.current_configuration['metadata']['fim_mode'] if mode is None else mode
                key_path = filter_events(events, ".[].data.path")

                for reg in reg_list:
                    expected_path = os.path.join(registry_key, reg)

                    if self.encoding is not None:
                        for index, item in enumerate(key_path):
                            key_path[index] = item.encode(encoding=self.encoding)

                    error_msg = f"Expected key path was '{expected_path}' but event key path is '{key_path}'"
                    assert (expected_path in key_path), error_msg

            def check_events_registry_value(events, key, value_list=['testvalue0'], mode=None):
                mode = global_parameters.current_configuration['metadata']['fim_mode'] if mode is None else mode
                key_path = filter_events(events, ".[].data.path")
                value_name = filter_events(events, ".[].data.value_name")

                for value in value_list:
                    error_msg = f"Expected value name was '{value}' but event value name is '{value_name}'"
                    assert (value in value_name), error_msg

                    error_msg = f"Expected key path was '{key}' but event key path is '{key_path}'"
                    assert (key in key_path), error_msg

            def filter_events(events, mask):
                """Returns a list of elements matching a specified mask in the events list using jq module."""
                if sys.platform in ("win32", 'sunos5', 'darwin'):
                    stdout = subprocess.check_output(["jq", "-r", mask], input=json.dumps(events).encode())

                    return stdout.decode("utf8").strip().split(os.linesep)
                else:
                    return jq(mask).transform(events, multiple_output=True)

            if self.events is not None:
                validate_checkers_per_event(self.events, self.options, mode)

                if self.is_value:
                    check_events_type(self.events, event_type, self.registry_dict)
                    check_events_registry_value(self.events, self.registry_key, value_list=self.registry_dict,
                                                mode=mode)
                else:
                    check_events_type(self.events, event_type, self.registry_dict)
                    check_events_key_path(self.events, self.registry_key, reg_list=self.registry_dict, mode=mode)

                if self.custom_validator is not None:
                    self.custom_validator.validate_after_cud(self.events)

                    if event_type == "added":
                        self.custom_validator.validate_after_create(self.events)
                    elif event_type == "modified":
                        self.custom_validator.validate_after_update(self.events)
                    elif event_type == "deleted":
                        self.custom_validator.validate_after_delete(self.events)

        def _get_elem_list(self):
            result_list = []

            for elem_name in self.registry_dict:
                if elem_name in self.registry_key:
                    continue

                expected_elem_path = os.path.join(self.registry_key, elem_name)
                result_list.append(expected_elem_path)

            return result_list

    def registry_value_cud(root_key, registry_sub_key, log_monitor, arch=KEY_WOW64_64KEY, value_list=['test_value'],
                           time_travel=False, min_timeout=1, options=None, triggers_event=True, triggers_event_add=True,
                           triggers_event_modified=True, triggers_event_delete=True, encoding=None,
                           callback=callback_value_event, validators_after_create=None, validators_after_update=None,
                           validators_after_delete=None, validators_after_cud=None, value_type=win32con.REG_SZ):
        """Check if creation, update and delete registry value events are detected by syscheck.

        This function provides multiple tools to validate events with custom validators.

        Args:
            root_key (str): root key (HKEY_LOCAL_MACHINE, HKEY_LOCAL_USER, etc).
            registry_sub_key (str): path of the subkey that will be created.
            log_monitor (FileMonitor): file event monitor.
            arch (int): Architecture of the registry key (KEY_WOW64_32KEY or KEY_WOW64_64KEY). Default `KEY_WOW64_64KEY`
            value_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with empty
                strings in each value. Default `['test_value']`
            time_travel (boolean, optional): Boolean to determine if there will be time travels or not. Default `False`
            min_timeout (int, optional): Minimum timeout. Default `1`
            options (set, optional): Set with all the checkers. Default `None`
            triggers_event (boolean, optional): Boolean to determine if the
                event should be raised or not. Default `True`
            triggers_event_add (boolean, optional): Boolean to determine if the added event should be raised.
                If triggers_event is false, this parameter is ignored.
            triggers_event_modified (boolean, optional): Boolean to determine if the modified event should be raised.
                If triggers_event is false, this parameter is ignored.
            triggers_event_delete (boolean, optional): Boolean to determine if the delete event should be raised.
                If triggers_event is false, this parameter is ignored.
            encoding (str, optional): String to determine the encoding of the registry value name. Default `None`
            callback (callable, optional): Callback to use with the log monitor. Default `callback_value_event`
            validators_after_create (list, optional): List of functions that validates an event triggered when a new
                registry value is created. Each function must accept a param to receive the event
                to be validated. Default `None`
            validators_after_update (list, optional): List of functions that validates an event triggered
                when a new registry value is modified. Each function must accept a param to receive the event
                to be validated. Default `None`
            validators_after_delete (list, optional): List of functions that validates an event triggered when a
                new registry value is deleted. Each function must accept a param to receive
                the event to be validated. Default `None`
            validators_after_cud (list, optional): List of functions that validates an event triggered when a
                new registry value is created, modified or deleted. Each function must accept a param to
                receive the event to be validated. Default `None`
        """
        # Transform registry list
        if root_key not in registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        if value_type in [win32con.REG_SZ, win32con.REG_MULTI_SZ]:
            value_added_content = 'added'
            value_default_content = ''
        else:
            value_added_content = 0
            value_default_content = 1

        aux_dict = {}
        if isinstance(value_list, list):
            for elem in value_list:
                aux_dict[elem] = (value_default_content, callback)

        elif isinstance(value_list, dict):
            for key, elem in value_list.items():
                aux_dict[key] = (elem, callback)

        else:
            raise ValueError('It can only be a list or dictionary')

        value_list = aux_dict

        options_set = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL]
        if options is not None:
            options_set = options_set.intersection(options)

        triggers_event_add = triggers_event and triggers_event_add
        triggers_event_modified = triggers_event and triggers_event_modified
        triggers_event_delete = triggers_event and triggers_event_delete

        custom_validator = CustomValidator(validators_after_create, validators_after_update,
                                           validators_after_delete, validators_after_cud)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=value_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=True)

        # Open the desired key
        key_handle = create_registry(registry_parser[root_key], registry_sub_key, arch)

        # Create registry values
        for name, _ in value_list.items():
            if name in registry_path:
                continue

            modify_registry_value(key_handle, name, value_type, value_added_content)

        check_time_travel(time_travel, monitor=log_monitor)
        registry_event_checker.fetch_and_check('added', min_timeout=min_timeout, triggers_event=triggers_event_add)

        if triggers_event_add:
            logger.info("'added' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))

            # Update the position of the log to the end of the scan
            if time_travel:
                log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                                  update_position=True,
                                  error_message=f'End of scheduled scan not detected after '
                                  f"{global_parameters.default_timeout} seconds")

        # Modify previous registry values
        for name, content in value_list.items():
            if name in registry_path:
                continue

            modify_registry_value(key_handle, name, value_type, content[0])

        check_time_travel(time_travel, monitor=log_monitor)
        registry_event_checker.fetch_and_check('modified', min_timeout=min_timeout,
                                               triggers_event=triggers_event_modified)

        if triggers_event_modified:
            logger.info("'modified' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))

            # Update the position of the log to the end of the scan
            if time_travel:
                log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                                  update_position=True,
                                  error_message=f'End of scheduled scan not detected after '
                                  f'{global_parameters.default_timeout} seconds')

        # Delete previous registry values
        for name, _ in value_list.items():
            if name in registry_path:
                continue

            delete_registry_value(key_handle, name)

        check_time_travel(time_travel, monitor=log_monitor)
        registry_event_checker.fetch_and_check('deleted', min_timeout=min_timeout, triggers_event=triggers_event_delete)

        if triggers_event_delete:
            logger.info("'deleted' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))

        # Update the position of the log to the end of the scan
        if time_travel:
            log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                              update_position=True,
                              error_message=f'End of scheduled scan not detected after '
                              f"{global_parameters.default_timeout} seconds")

    def transform_registry_list(value_list=['test_value'], value_type=win32con.REG_SZ, callback=callback_value_event):

        if value_type in [win32con.REG_SZ, win32con.REG_MULTI_SZ]:
            value_default_content = ''
        else:
            value_default_content = 1

        aux_dict = {}
        if isinstance(value_list, list):
            for elem in value_list:
                aux_dict[elem] = (value_default_content, callback)

        elif isinstance(value_list, dict):
            for key, elem in value_list.items():
                aux_dict[key] = (elem, callback)

        else:
            raise ValueError('It can only be a list or dictionary')

        return aux_dict

    def set_check_options(options):
        """ Return set of check options. If options given is none, it will return check_all"""
        options_set = REQUIRED_REG_VALUE_ATTRIBUTES[CHECK_ALL]
        if options is not None:
            options_set = options_set.intersection(options)
        return options_set

    def create_values_content(value_name, size):
        """ Create a string of data content of a given size for a specific key value"""
        return {value_name: generate_string(size, '0')}

    def registry_value_create(root_key, registry_sub_key, log_monitor, arch=KEY_WOW64_64KEY, value_list=['test_value'],
                              min_timeout=1, options=None, wait_for_scan=False, scan_delay=10, triggers_event=True,
                              encoding=None, callback=callback_value_event, validators_after_create=None,
                              value_type=win32con.REG_SZ):
        """Check if creation of registry value events are detected by syscheck.

        This function provides multiple tools to validate events with custom validators.

        Args:
            root_key (str): root key (HKEY_LOCAL_MACHINE, HKEY_LOCAL_USER, etc).
            registry_sub_key (str): path of the subkey that will be created.
            log_monitor (FileMonitor): file event monitor.
            arch (int): Architecture of the registry key (KEY_WOW64_32KEY or KEY_WOW64_64KEY). Default `KEY_WOW64_64KEY`
            value_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with empty
                strings in each value. Default `['test_value']`
            min_timeout (int, optional): Minimum timeout. Default `1`
            options (set, optional): Set with all the checkers. Default `None`
            wait_for_scan (boolean, optional): Boolean to determine if there will be time travels or not.
                Default `False`
            scan_delay (int, optional): time the test sleeps waiting for scan to be triggered.
            triggers_event (boolean, optional): Boolean to determine if the
                event should be raised or not. Default `True`
            encoding (str, optional): String to determine the encoding of the registry value name. Default `None`
            callback (callable, optional): Callback to use with the log monitor. Default `callback_value_event`
            validators_after_create (list, optional): List of functions that validates an event triggered when a new
                registry value is created. Each function must accept a param to receive the event
                to be validated. Default `None`
        """
        # Transform registry list
        if root_key not in registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        value_list = transform_registry_list(value_list)
        if value_type in [win32con.REG_SZ, win32con.REG_MULTI_SZ]:
            value_added_content = 'added'
        else:
            value_added_content = 0

        options_set = set_check_options(options)

        custom_validator = CustomValidator(validators_after_create, None, None, None)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=value_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=True)

        # Open the desired key
        key_handle = create_registry(registry_parser[root_key], registry_sub_key, arch)

        # Create registry values
        for name, _ in value_list.items():
            if name in registry_path:
                continue
            modify_registry_value(key_handle, name, value_type, value_added_content)

        wait_for_scheduled_scan(wait_for_scan=wait_for_scan, interval=scan_delay, monitor=log_monitor)

        registry_event_checker.fetch_and_check('added', min_timeout=min_timeout, triggers_event=triggers_event)

        if triggers_event:
            logger.info("'added' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))

    def registry_value_update(root_key, registry_sub_key, log_monitor, arch=KEY_WOW64_64KEY, value_list=['test_value'],
                              wait_for_scan=False, scan_delay=10, min_timeout=1, options=None, triggers_event=True,
                              encoding=None, callback=callback_value_event, validators_after_update=None,
                              value_type=win32con.REG_SZ):
        """Check if update registry value events are detected by syscheck.

        This function provides multiple tools to validate events with custom validators.

        Args:
            root_key (str): root key (HKEY_LOCAL_MACHINE, HKEY_LOCAL_USER, etc).
            registry_sub_key (str): path of the subkey that will be created.
            log_monitor (FileMonitor): file event monitor.
            arch (int): Architecture of the registry key (KEY_WOW64_32KEY or KEY_WOW64_64KEY). Default `KEY_WOW64_64KEY`
            value_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with empty
                strings in each value. Default `['test_value']`
            wait_for_scan (boolean, optional): Boolean to determine if there will waits for scheduled scans.
                Default `False`
            scan_delay (int, optional): time the test sleeps waiting for scan to be triggered.
            min_timeout (int, optional): Minimum timeout. Default `1`
            options (set, optional): Set with all the checkers. Default `None`
            triggers_event (boolean, optional): Boolean to determine if the
                event should be raised or not. Default `True`
            encoding (str, optional): String to determine the encoding of the registry value name. Default `None`
            callback (callable, optional): Callback to use with the log monitor. Default `callback_value_event`
            validators_after_update (list, optional): List of functions that validates an event triggered
                when a new registry value is modified. Each function must accept a param to receive the event
                to be validated. Default `None`
        """
        # Transform registry list
        if root_key not in registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        value_list = transform_registry_list(value_list=value_list, value_type=value_type, callback=callback)

        options_set = set_check_options(options)

        custom_validator = CustomValidator(None, validators_after_update, None, None)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=value_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=True)

        key_handle = create_registry(registry_parser[root_key], registry_sub_key, arch)

        # Modify previous registry values
        for name, content in value_list.items():
            if name in registry_path:
                continue

            modify_registry_value(key_handle, name, value_type, content[0])

        wait_for_scheduled_scan(wait_for_scan=wait_for_scan, interval=scan_delay, monitor=log_monitor)
        registry_event_checker.fetch_and_check('modified', min_timeout=min_timeout, triggers_event=triggers_event)

        if triggers_event:
            logger.info("'modified' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))

    def registry_value_delete(root_key, registry_sub_key, log_monitor, arch=KEY_WOW64_64KEY, value_list=['test_value'],
                              wait_for_scan=False, scan_delay=10, min_timeout=1, options=None, triggers_event=True,
                              encoding=None, callback=callback_value_event, validators_after_delete=None,
                              value_type=win32con.REG_SZ):
        """Check if delete registry value events are detected by syscheck.

        This function provides multiple tools to validate events with custom validators.

        Args:
            root_key (str): root key (HKEY_LOCAL_MACHINE, HKEY_LOCAL_USER, etc).
            registry_sub_key (str): path of the subkey that will be created.
            log_monitor (FileMonitor): file event monitor.
            arch (int): Architecture of the registry key (KEY_WOW64_32KEY or KEY_WOW64_64KEY). Default `KEY_WOW64_64KEY`
            value_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with empty
                strings in each value. Default `['test_value']`
            wait_for_scan (boolean, optional): Boolean to determine if there will waits for scheduled scans.
                Default `False`
            scan_delay (int, optional): time the test sleeps waiting for scan to be triggered.
            min_timeout (int, optional): Minimum timeout. Default `1`
            options (set, optional): Set with all the checkers. Default `None`
            triggers_event (boolean, optional): Boolean to determine if the
                event should be raised or not. Default `True`
            encoding (str, optional): String to determine the encoding of the registry value name. Default `None`
            callback (callable, optional): Callback to use with the log monitor. Default `callback_value_event`
            validators_after_delete (list, optional): List of functions that validates an event triggered
                when a new registry value is deleted. Each function must accept a param to receive the event
                to be validated. Default `None`
        """
        # Transform registry list
        if root_key not in registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        value_list = transform_registry_list(value_list=value_list, value_type=value_type, callback=callback)

        options_set = set_check_options(options)

        custom_validator = CustomValidator(None, None, validators_after_delete, None)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=value_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=True)

        key_handle = create_registry(registry_parser[root_key], registry_sub_key, arch)

        # Delete previous registry values
        for name, _ in value_list.items():
            if name in registry_path:
                continue
            delete_registry_value(key_handle, name)

        wait_for_scheduled_scan(wait_for_scan=wait_for_scan, interval=scan_delay, monitor=log_monitor)
        registry_event_checker.fetch_and_check('deleted', min_timeout=min_timeout, triggers_event=triggers_event)

        if triggers_event:
            logger.info("'deleted' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))

    def registry_key_cud(root_key, registry_sub_key, log_monitor, arch=KEY_WOW64_64KEY, key_list=['test_key'],
                         time_travel=False, min_timeout=1, options=None, triggers_event=True, triggers_event_add=True,
                         triggers_event_modified=True, triggers_event_delete=True, encoding=None,
                         callback=callback_key_event, validators_after_create=None, validators_after_update=None,
                         validators_after_delete=None, validators_after_cud=None):
        """Check if creation, update and delete registry key events are detected by syscheck.

        This function provides multiple tools to validate events with custom validators.

        Args:
            root_key (str): Root key (HKEY_LOCAL_MACHINE, HKEY_LOCAL_USER, etc).
            registry_sub_key (str): Path of the subkey that will be created
            log_monitor (FileMonitor): File event monitor.
            arch (int): Architecture of the registry key (KEY_WOW64_32KEY or KEY_WOW64_64KEY). Default `KEY_WOW64_64KEY`
            key_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with
                empty strings in each value. Default `['test_key']`
            time_travel (boolean, optional): Boolean to determine if there will be time travels or not. Default `False`
            min_timeout (int, optional): Minimum timeout. Default `1`
            options (set, optional): Set with all the checkers. Default `None`
            triggers_event (boolean, optional): Boolean to determine if the event
                should be raised or not. Default `True`
            triggers_event_add (boolean, optional): Boolean to determine if the added event should be raised.
                If triggers_event is false, this parameter is ignored.
            triggers_event_modified (boolean, optional): Boolean to determine if the modified event should be raised.
                If triggers_event is false, this parameter is ignored.
            triggers_event_delete (boolean, optional): Boolean to determine if the delete event should be raised.
                If triggers_event is false, this parameter is ignored.
            encoding (str, optional): String to determine the encoding of the registry value name. Default `None`
            callback (callable, optional): Callback to use with the log monitor. Default `callback_detect_event`
            validators_after_create (list, optional): List of functions that validates an event triggered when a new
                registry value is created. Each function must accept a param to receive the
                event to be validated. Default `None`
            validators_after_update (list, optional): List of functions that validates an event triggered when
                a new registry value is modified. Each function must accept a param to receive the
                event to be validated. Default `None`
            validators_after_delete (list, optional): List of functions that validates an event triggered when a
                new registry value is deleted. Each function must accept a param to receive the event
                to be validated. Default `None`
            validators_after_cud (list, optional): List of functions that validates an event triggered when a
                new registry value is created, modified or deleted. Each function must accept a param to
                receive the event to be validated. Default `None`
        """
        # Transform registry list
        if root_key not in registry_parser:
            raise ValueError("Registry_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        aux_dict = {}
        if isinstance(key_list, list):
            for elem in key_list:
                aux_dict[elem] = ('', callback)

        elif isinstance(key_list, dict):
            for key, elem in key_list.items():
                aux_dict[key] = (elem, callback)
        else:
            raise ValueError('It can only be a list or dictionary')

        key_list = aux_dict

        options_set = REQUIRED_REG_KEY_ATTRIBUTES[CHECK_ALL]
        if options is not None:
            options_set = options_set.intersection(options)

        triggers_event_add = triggers_event and triggers_event_add
        triggers_event_modified = triggers_event and triggers_event_modified
        triggers_event_delete = triggers_event and triggers_event_delete

        custom_validator = CustomValidator(validators_after_create, validators_after_update,
                                           validators_after_delete, validators_after_cud)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=key_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=False)

        # Open the desired key
        create_registry(registry_parser[root_key], registry_sub_key, arch)

        # Create registry subkeys
        for name, _ in key_list.items():
            if name in registry_path:
                continue

            create_registry(registry_parser[root_key], os.path.join(registry_sub_key, name), arch)

        check_time_travel(time_travel, monitor=log_monitor)
        registry_event_checker.fetch_and_check('added', min_timeout=min_timeout, triggers_event=triggers_event_add)

        if triggers_event_add:
            logger.info("'added' {} detected as expected.\n".format("events" if len(key_list) > 1 else "event"))

            # Update the position of the log to the end of the scan
            if time_travel:
                log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                                  update_position=True,
                                  error_message=f'End of scheduled scan not detected after '
                                  f"{global_parameters.default_timeout} seconds")

        # Modify previous registry subkeys
        for name, _ in key_list.items():
            if name in registry_path:
                continue

            modify_registry(registry_parser[root_key], os.path.join(registry_sub_key, name), arch)

        check_time_travel(time_travel, monitor=log_monitor)
        registry_event_checker.fetch_and_check('modified', min_timeout=min_timeout,
                                               triggers_event=triggers_event_modified)

        if triggers_event_modified:
            logger.info("'modified' {} detected as expected.\n".format("events" if len(key_list) > 1 else "event"))

            # Update the position of the log to the end of the scan
            if time_travel:
                log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                                  update_position=True,
                                  error_message=f'End of scheduled scan not detected after '
                                  f"{global_parameters.default_timeout} seconds")

        # Delete previous registry subkeys
        for name, _ in key_list.items():
            if name in registry_path:
                continue

            delete_registry(registry_parser[root_key], os.path.join(registry_sub_key, name), arch)

        check_time_travel(time_travel, monitor=log_monitor)
        registry_event_checker.fetch_and_check('deleted', min_timeout=min_timeout, triggers_event=triggers_event_delete)

        if triggers_event_delete:
            logger.info("'deleted' {} detected as expected.\n".format("events" if len(key_list) > 1 else "event"))

            # Update the position of the log to the end of the scan
            if time_travel:
                log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                                  update_position=True,
                                  error_message=f'End of scheduled scan not detected after '
                                  f"{global_parameters.default_timeout} seconds")


class CustomValidator:
    """Enable using user-defined validators over the events when validating them with EventChecker"""

    def __init__(self, validators_after_create=None, validators_after_update=None,
                 validators_after_delete=None, validators_after_cud=None):
        self.validators_create = validators_after_create
        self.validators_update = validators_after_update
        self.validators_delete = validators_after_delete
        self.validators_cud = validators_after_cud

    def validate_after_create(self, events):
        """Custom validators to be applied by default when the event_type is 'added'.

        Args:
            events (list): list of events to be validated.
        """
        if self.validators_create is not None:
            for event in events:
                for validator in self.validators_create:
                    validator(event)

    def validate_after_update(self, events):
        """Custom validators to be applied by default when the event_type is 'modified'.

        Args:
            events (list): list of events to be validated.
        """
        if self.validators_update is not None:
            for event in events:
                for validator in self.validators_update:
                    validator(event)

    def validate_after_delete(self, events):
        """Custom validators to be applied by default when the event_type is 'deleted'.

        Args:
            events (list): list of events to be validated.
        """
        if self.validators_delete is not None:
            for event in events:
                for validator in self.validators_delete:
                    validator(event)

    def validate_after_cud(self, events):
        """Custom validators to be applied always by default.

        Args:
            events (list): list of events to be validated.
        """
        if self.validators_cud is not None:
            for event in events:
                for validator in self.validators_cud:
                    validator(event)


def calculate_registry_diff_paths(reg_key, reg_subkey, arch, value_name):
    """Calculate the diff folder path of a value.

    Args:
        reg_key (str): registry name (HKEY_* constants).
        reg_subkey (str): path of the subkey.
        arch (int): architecture of the registry.
        value_name (str): name of the value.

    Returns:
        tuple: diff folder path of the key and the path of the value.
    """
    key_path = os.path.join(reg_key, reg_subkey)
    folder_path = "{} {}".format("[x32]" if arch == KEY_WOW64_32KEY else "[x64]",
                                 sha1(key_path.encode()).hexdigest())
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_path,
                             sha1(value_name.encode()).hexdigest(), 'last-entry.gz')
    return (folder_path, diff_file)


def detect_initial_scan(file_monitor):
    """Detect initial scan when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_end_scan,
                       error_message='Did not receive expected "File integrity monitoring scan ended" event')


def detect_initial_scan_start(file_monitor):
    """Detect initial scan start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_detect_scan_start,
                       error_message='Did not receive expected "File integrity monitoring scan started" event')


def detect_sync_initial_scan_start(file_monitor):
    """Detect initial sync scan start.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_start_synchronization,
                       error_message='Did not receive expected "FIM sync scan started" event')


def detect_realtime_start(file_monitor):
    """Detect realtime engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_num_inotify_watches,
                       error_message='Did not receive expected "Folders monitored with real-time engine..." event')


def detect_whodata_start(file_monitor):
    """Detect whodata engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=60, callback=callback_real_time_whodata_started,
                       error_message='Did not receive expected'
                                     '"File integrity monitoring real-time Whodata engine started" event')


def get_scan_timestamp(file_monitor):
    """Get the timestamp for the for the end of a scan

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    timestamp = file_monitor.start(timeout=60, callback=callback_get_scan_timestap,
                                   error_message='Did not receive expected '
                                   '"File integrity monitoring scan ended" event').result()
    return timestamp


def wait_for_audit(whodata, monitor):
    """Wait for the audit callback if we are using whodata monitoring.
    Args:
        whodata (boolean): True if whodata is active.
        monitor (FileMonitor): LogMonitor to use.
    """
    if whodata:
        monitor.start(timeout=35, callback=callback_end_audit_reload_rules, update_position=False,
                      error_message='Did not receive expected "Audit rules reloaded..." event')


def generate_params(extra_params: dict = None, apply_to_all: Union[Sequence[Any], Generator[dict, None, None]] = None,
                    modes: list = None):
    """
    Expand params and metadata with optional FIM modes .

        extra_params = {'WILDCARD': {'attribute': ['list', 'of', 'values']}} - Max. 3 elements in the list of values
                            or
                    {'WILDCARD': {'attribute': 'value'}} - It will have the same value for scheduled, realtime and
                                                            whodata
                            or
                    {'WILDCARD': 'value'} - Valid when param is not an attribute. (ex: 'MODULE_NAME': __name__)
                            or
                    {'WILDCARD': ['list', 'of', 'values']} - Same as above with multiple values. The length of the list
                                                                must be the same as the length of the mode list.


        apply_to_all = Same structure as above. The difference is, these params will be applied for every existing
                        configuration. They are applied after the `extra_params`.

    Examples:
        >>> generate_params(extra_params={'REPORT_CHANGES': {'report_changes': ['yes', 'no']}, 'MODULE_NAME': 'name'},
        ...                 modes=['realtime', 'whodata'])
        ([{'FIM_MODE': {'realtime': 'yes'}, 'REPORT_CHANGES': {'report_changes': 'yes'}, 'MODULE_NAME': 'name'},
        {'FIM_MODE': {'whodata': 'yes'}, 'REPORT_CHANGES': {'report_changes': 'no'}, 'MODULE_NAME': 'name'}],
        [{'fim_mode': 'realtime', 'report_changes': 'yes', 'module_name': 'name'},
        {'fim_mode': 'whodata', 'report_changes': 'no', 'module_name': 'name'}])

        >>> generate_params(extra_params={'MODULE_NAME': 'name'}, apply_to_all={'FREQUENCY': {'frequency': [1, 2]}},
        ...                 modes=['scheduled', 'realtime'])
        ([{'FIM_MODE': '', 'MODULE_NAME': 'name', 'FREQUENCY': {'frequency': 1}},
        {'FIM_MODE': {'realtime': 'yes'}, 'MODULE_NAME': 'name', 'FREQUENCY': {'frequency': 1}},
        {'FIM_MODE': '', 'MODULE_NAME': 'name', 'FREQUENCY': {'frequency': 2}},
        {'FIM_MODE': {'realtime': 'yes'}, 'MODULE_NAME': 'name', 'FREQUENCY': {'frequency': 2}}],
        [{'fim_mode': 'scheduled', 'module_name': 'name', 'frequency': {'frequency': 1}},
        {'fim_mode': 'realtime', 'module_name': 'name', 'frequency': {'frequency': 1}},
        {'fim_mode': 'scheduled', 'module_name': 'name', 'frequency': {'frequency': 2}},
        {'fim_mode': 'realtime', 'module_name': 'name', 'frequency': {'frequency': 2}}])

        >>> generate_params(extra_params={'LIST_OF_VALUES': {'list': [[1,2,3]]}, 'MODULE_NAME': 'name'},
        ...                 modes=['scheduled'])
        ([{'FIM_MODE': '', 'LIST_OF_VALUES': {'list': [1, 2, 3]}, 'MODULE_NAME': 'name'}],
        [{'fim_mode': 'scheduled', 'list_of_values': [1, 2, 3], 'module_name': 'name'}])

    Args:
        extra_params (dict, optional): Dictionary with all the extra parameters to add for every mode. Default `None`
        apply_to_all (iterable object or generator object): dictionary with all the extra parameters to add to
            every configuration. Default `None`
        modes (list, optional): FIM modes to be applied. Default `None` (scheduled, realtime and whodata)

    Returns:
        tuple (list, list): Tuple with the list of parameters and the list of metadata.
    """

    def transform_param(mutable_object: dict):
        """Transform `mutable_object` into a valid data structure."""
        for k, v in mutable_object.items():
            if isinstance(v, dict):
                for v_key, v_value in v.items():
                    mutable_object[k][v_key] = v_value if isinstance(v_value, list) else [v_value] * len(modes)
            elif not isinstance(v, list):
                mutable_object[k] = [v] * len(modes)

    fim_param = []
    fim_metadata = []

    # Get FIM params and metadata
    modes = modes if modes else ['scheduled', 'realtime', 'whodata']
    for mode in modes:
        param, metadata = get_fim_mode_param(mode)
        if param:
            fim_param.append(param)
            fim_metadata.append(metadata)

    # If we have extra_params to add, assert they have the exact number of elements as modes
    # Also, if there aren't extra_params, let `add` to False to at least put `FIM_MODES`
    add = False
    if extra_params:
        transform_param(extra_params)
        for _, value in extra_params.items():
            if isinstance(value, dict):
                assert len(next(iter(value.values()))) == len(modes), 'Length not equal between extra_params values ' \
                                                                      'and modes'
            else:
                assert len(value) == len(modes), 'Length not equal between extra_params values and modes'
        add = True

    params = []
    metadata = []

    # Iterate over fim_mode params and metadata and add one configuration for every existing fim_mode
    for i, (fim_mode_param, fim_mode_meta) in enumerate(zip(fim_param, fim_metadata)):
        p_aux: dict = deepcopy(fim_mode_param)
        m_aux: dict = deepcopy(fim_mode_meta)
        if add:
            for key, value in extra_params.items():
                p_aux[key] = {k: v[i] for k, v in value.items()} if isinstance(value, dict) else \
                    value[i] if isinstance(value, list) else value
                m_aux[key.lower()] = next(iter(value.values()))[i] if isinstance(value, dict) else \
                    value[i] if isinstance(value, list) else value
        params.append(p_aux)
        metadata.append(m_aux)

    # Append new parameters and metadata for every existing configuration
    if apply_to_all:
        aux_params = deepcopy(params)
        aux_metadata = deepcopy(metadata)
        params.clear()
        metadata.clear()
        for element in apply_to_all:
            for p_dict, m_dict in zip(aux_params, aux_metadata):
                params.append({**p_dict, **element})
                metadata.append({**m_dict, **{wildcard.lower(): value for wildcard, value in element.items()}})

    return params, metadata


def get_fim_mode_param(mode, key='FIM_MODE'):
    """Get the parameters for the FIM mode.

    This is useful to generate the directories tag with several fim modes. It also
    takes into account the current platform so realtime and whodata does not apply
    to darwin.

    Args:
        mode (string): Must be one of the following 'scheduled', 'realtime' or 'whodata'
        key (string, optional): Name of the placeholder expected in the target configuration. Default 'FIM_MODE'

    Returns:
        tuple (dict, dict):
            Params: The key is `key` and the value is the string to be replaced in the target configuration.
            Metadata: The key is `key` in lowercase and the value is always `mode`.
    """

    if mode not in global_parameters.fim_mode:
        return None, None

    metadata = {key.lower(): mode}
    if mode == 'scheduled':
        return {key: ''}, metadata
    elif mode == 'realtime' and sys.platform not in _os_excluded_from_rt_wd:
        return {key: {'realtime': 'yes'}}, metadata
    elif mode == 'whodata' and sys.platform not in _os_excluded_from_rt_wd:
        return {key: {'whodata': 'yes'}}, metadata
    else:
        return None, None


def check_fim_start(file_monitor):
    """Check if realtime starts, whodata starts or ends the initial FIM scan.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events.
    """
    mode = global_parameters.current_configuration['metadata']['fim_mode']
    if mode == 'realtime':
        detect_realtime_start(file_monitor)
    elif mode == 'whodata':
        detect_whodata_start(file_monitor)
    else:
        detect_initial_scan(file_monitor)


# Create folder and file inside
def create_folder_file(host_manager, folder_path):
    # Create folder
    host_manager.run_command('wazuh-agent1', f'mkdir {folder_path}')

    # Create file
    host_manager.run_command('wazuh-agent1', f'touch {folder_path}/{folder_path}.txt')


# Check that fim scan end
def wait_for_fim_scan_end(HostMonitor, inventory_path, messages_path, tmp_path):
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()


# Function that use to run a script inside remote host to execute queries to DB
def query_db(host_manager, script, db_path, query):
    return host_manager.run_command('wazuh-manager', "python {} --db_path {} --query {}".format(script, db_path, query))
