# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import time
import platform
from datetime import datetime, timedelta
from typing import Sequence, Union, Generator, Any
from copy import deepcopy
from hashlib import sha1

from wazuh_testing import global_parameters, logger, REGULAR, LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.file import create_file, modify_file_content, delete_file, generate_string
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.modules import fim
from wazuh_testing.modules.fim import event_monitor as ev
from wazuh_testing.modules.fim.classes import CustomValidator, EventChecker, RegistryEventChecker


if sys.platform == 'win32':
    import win32con
    import win32api
    import win32security as win32sec
    import ntsecuritycon as ntc
    import pywintypes


# Variables
_os_excluded_from_rt_wd = ['darwin', 'sunos5']


# Functions
def get_sync_msgs(timeout, new_data=True):
    """Look for as many synchronization events as possible.

    This function will look for the synchronization messages until a Timeout is raised or 'max_events' is reached.

    Args:
        timeout (int): Timeout that will be used to get the dbsync_no_data message.
        new_data (bool): Specifies if the test will wait the event `dbsync_no_data`.

    Returns:
        A list with all the events in json format.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    events = []
    if new_data:
        wazuh_log_monitor.start(timeout=timeout,
                                callback=generate_monitoring_callback(ev.CB_REGISTRY_DBSYNC_NO_DATA),
                                error_message='Did not receive expected '
                                              '"db sync no data" event')
    for _ in range(0, fim.MAX_EVENTS_VALUE):
        try:
            sync_event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                 callback=ev.callback_detect_registry_integrity_state_event,
                                                 accum_results=1,
                                                 error_message='Did not receive expected '
                                                               'Sending integrity control message"').result()
        except TimeoutError:
            break
        events.append(sync_event)
    return events


def find_value_in_event_list(key_path, value_name, event_list):
    """Function that looks for a key path and value_name in a list of json events.

    Args:
        path (str): Path of the registry key.
        value_name (str): Name of the value.
        event_list (list): List containing the events in JSON format.

    Returns:
        The event that matches the specified path. None if no event was found.
    """
    for event in event_list:
        if 'value_name' not in event.keys():
            continue
        if str(event['path']) == key_path and event['value_name'] == value_name:
            return event
    return None


def create_values_content(value_name, size):
    """ Create a string of data content of a given size for a specific key value"""
    return {value_name: generate_string(size, '0')}


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
            new_key = win32api.RegCreateKeyEx(key, subkey, win32con.KEY_ALL_ACCESS | arch)
            logger.info("Created registry key " + str(os.path.join(fim.registry_class_name[key], subkey)))
            return new_key[0]  # Ignore the flag that RegCreateKeyEx returns
        except OSError as e:
            logger.warning(f"Registry could not be created: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry could not be created: {e}")


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
        print_arch = '[x64]' if arch == fim.KEY_WOW64_64KEY else '[x32]'
        logger.info(f"- Changing permissions of {print_arch}{os.path.join(fim.registry_class_name[key], subkey)}")

        try:
            key_h = fim.RegOpenKeyEx(key, subkey, 0, fim.KEY_ALL_ACCESS | arch)
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
        print_arch = '[x64]' if arch == fim.KEY_WOW64_64KEY else '[x32]'
        logger.info(f"- Changing mtime of {print_arch}{os.path.join(fim.registry_class_name[key], subkey)}")

        try:
            key_h = fim.RegOpenKeyEx(key, subkey, 0, fim.KEY_ALL_ACCESS | arch)

            modify_registry_value(key_h, "dummy_value", fim.REG_SZ, "this is a dummy value")
            time.sleep(2)
            delete_registry_value(key_h, "dummy_value")

            fim.RegCloseKey(key_h)
            key_h = fim.RegOpenKeyEx(key, subkey, 0, fim.KEY_ALL_ACCESS)
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
        print_arch = '[x64]' if arch == fim.KEY_WOW64_64KEY else '[x32]'
        logger.info(f"- Changing owner of {print_arch}{os.path.join(fim.registry_class_name[key], subkey)}")

        try:
            key_h = fim.RegOpenKeyEx(key, subkey, 0, fim.KEY_ALL_ACCESS | arch)
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
    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == fim.KEY_WOW64_64KEY else '[x32]'
        logger.info(f"Modifying registry key {print_arch}{os.path.join(fim.registry_class_name[key], subkey)}")

        modify_key_perms(key, subkey, arch, win32sec.LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")[0])
        modify_registry_owner(key, subkey, arch,
                              win32sec.LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")[0])
        modify_registry_key_mtime(key, subkey, arch)


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
            logger.info(f"Modifying value '{value_name}' of type {fim.registry_value_type[type]} and value '{value}'")
            win32api.RegSetValueEx(key_h, value_name, 0, type, value)
        except OSError as e:
            logger.warning(f"Could not modify registry value content: {e}")
        except pywintypes.error as e:
            logger.warning(f"Could not modify registry value content: {e}")


def delete_registry(key, subkey, arch):
    """Delete a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """
    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == fim.KEY_WOW64_64KEY else '[x32]'
        logger.info(f"Removing registry key {print_arch}{str(os.path.join(fim.registry_class_name[key], subkey))}")

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)
            win32api.RegDeleteTree(key_h, None)
            win32api.RegDeleteKeyEx(key, subkey, samDesired=arch)
        except OSError as e:
            logger.warning(f"Couldn't remove key {str(os.path.join(fim.registry_class_name[key], subkey))}: {e}")
        except pywintypes.error as e:
            logger.warning(f"Couldn't remove key {str(os.path.join(fim.registry_class_name[key], subkey))}: {e}")


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
    folder_path = "{} {}".format("[x32]" if arch == fim.KEY_WOW64_32KEY else "[x64]",
                                 sha1(key_path.encode()).hexdigest())
    diff_file = os.path.join(WAZUH_PATH, 'queue', 'diff', 'registry', folder_path,
                             sha1(value_name.encode()).hexdigest(), 'last-entry.gz')
    return (folder_path, diff_file)


def transform_registry_list(value_list=['test_value'], value_type=fim.REG_SZ, callback=ev.callback_value_event):
    """Transform a list of registry values into a dictionary.
    Args:
        value list (List): list of string value names
        value type (str): type of registry value that is expected.
        Callback (object): Callback to pair with the value to be monitored.
    Returns:
        Dict: dictionary with the values and the corresponding callbacks to monitor them.
    """
    if sys.platform == 'win32':
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


def transform_registry_key_list(key_list=['test_key'], callback=ev.callback_key_event):
    """Transform a list of registry keys into a dictionary.
    Args:
        key_list list (List): list of strings with the key names names
        Callback (object): Callback to pair with the key to be monitored.
    Returns:
        Dict: dictionary with the keys and the corresponding callbacks to monitor them.
    """
    if sys.platform == 'win32':
        aux_dict = {}
        if isinstance(key_list, list):
            for elem in key_list:
                aux_dict[elem] = ('', callback)

        elif isinstance(key_list, dict):
            for key, elem in key_list.items():
                aux_dict[key] = (elem, callback)
        else:
            raise ValueError('It can only be a list or dictionary')

        return aux_dict


def set_check_options(options):
    """ Return set of check options. If options given is none, it will return check_all"""
    options_set = fim.REQUIRED_REG_VALUE_ATTRIBUTES[fim.CHECK_ALL]
    if options is not None:
        options_set = options_set.intersection(options)
    return options_set


def registry_value_create(root_key, registry_sub_key, log_monitor, arch=fim.KEY_WOW64_64KEY, value_list=['test_value'],
                          min_timeout=1, options=None, wait_for_scan=False, scan_delay=10, triggers_event=True,
                          encoding=None, callback=ev.callback_value_event, validators_after_create=None,
                          value_type=fim.REG_SZ):
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
    if sys.platform == 'win32':
        # Transform registry list
        if root_key not in fim.registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        value_list = transform_registry_list(value_list)
        if value_type in [fim.REG_SZ, fim.REG_MULTI_SZ]:
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
        key_handle = create_registry(fim.registry_parser[root_key], registry_sub_key, arch)

        # Create registry values
        for name, _ in value_list.items():
            if name in registry_path:
                continue
            modify_registry_value(key_handle, name, value_type, value_added_content)

        wait_for_scheduled_scan(wait_for_scan=wait_for_scan, interval=scan_delay, monitor=log_monitor)

        registry_event_checker.fetch_and_check('added', min_timeout=min_timeout, triggers_event=triggers_event)

        if triggers_event:
            logger.info("'added' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))


def registry_value_update(root_key, registry_sub_key, log_monitor, arch=fim.KEY_WOW64_64KEY, value_list=['test_value'],
                          wait_for_scan=False, scan_delay=10, min_timeout=1, options=None, triggers_event=True,
                          encoding=None, callback=ev.callback_value_event, validators_after_update=None,
                          value_type=fim.REG_SZ):
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
    if sys.platform == 'win32':
        # Transform registry list
        if root_key not in fim.registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        value_list = transform_registry_list(value_list=value_list, value_type=value_type, callback=callback)

        options_set = set_check_options(options)

        custom_validator = CustomValidator(None, validators_after_update, None, None)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=value_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=True)

        key_handle = create_registry(fim.registry_parser[root_key], registry_sub_key, arch)

        # Modify previous registry values
        for name, content in value_list.items():
            if name in registry_path:
                continue

            modify_registry_value(key_handle, name, value_type, content[0])

        wait_for_scheduled_scan(wait_for_scan=wait_for_scan, interval=scan_delay, monitor=log_monitor)
        registry_event_checker.fetch_and_check('modified', min_timeout=min_timeout, triggers_event=triggers_event)

        if triggers_event:
            logger.info("'modified' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))


def registry_value_delete(root_key, registry_sub_key, log_monitor, arch=fim.KEY_WOW64_64KEY, value_list=['test_value'],
                          wait_for_scan=False, scan_delay=10, min_timeout=1, options=None, triggers_event=True,
                          encoding=None, callback=ev.callback_value_event, validators_after_delete=None,
                          value_type=fim.REG_SZ):
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
        triggers_event (boolean, optional): Boolean to determine if the event should be raised or not. Default `True`
        encoding (str, optional): String to determine the encoding of the registry value name. Default `None`
        callback (callable, optional): Callback to use with the log monitor. Default `callback_value_event`
        validators_after_delete (list, optional): List of functions that validates an event triggered
        when a new registry value is deleted. Each function must accept a param to receive the event
        to be validated. Default `None`
    """
    if sys.platform == 'win32':
        # Transform registry list
        if root_key not in fim.registry_parser:
            raise ValueError("root_key not valid")

        registry_path = os.path.join(root_key, registry_sub_key)

        value_list = transform_registry_list(value_list=value_list, value_type=value_type, callback=callback)

        options_set = set_check_options(options)

        custom_validator = CustomValidator(None, None, validators_after_delete, None)

        registry_event_checker = RegistryEventChecker(log_monitor=log_monitor, registry_key=registry_path,
                                                      registry_dict=value_list, options=options_set,
                                                      custom_validator=custom_validator, encoding=encoding,
                                                      callback=callback, is_value=True)

        key_handle = create_registry(fim.registry_parser[root_key], registry_sub_key, arch)

        # Delete previous registry values
        for name, _ in value_list.items():
            if name in registry_path:
                continue
            delete_registry_value(key_handle, name)

        wait_for_scheduled_scan(wait_for_scan=wait_for_scan, interval=scan_delay, monitor=log_monitor)
        registry_event_checker.fetch_and_check('deleted', min_timeout=min_timeout, triggers_event=triggers_event)

        if triggers_event:
            logger.info("'deleted' {} detected as expected.\n".format("events" if len(value_list) > 1 else "event"))


# Old Configuration framework
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


def regular_file_cud(folder, log_monitor, file_list=['testfile0'], min_timeout=1, options=None, triggers_event=True,
                     triggers_modified_event=True, encoding=None, validators_after_create=None, validators_after_update=None,
                     validators_after_delete=None, validators_after_cud=None, event_mode=None, escaped=False):
    """Check if creation, update and delete events are detected by syscheck.

    This function provides multiple tools to validate events with custom validators.

    Args:
        folder (str): Path where the files will be created.
        log_monitor (FileMonitor): File event monitor.
        file_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with
            empty strings in each value. Default `['testfile0']`
        min_timeout (int, optional): Minimum timeout. Default `1`
        options (set, optional): Set with all the checkers. Default `None`
        triggers_event (boolean, optional): Boolean to determine if the event should be raised or not. Default `True`
        encoding (str, optional): String to determine the encoding of the file name. Default `None`
        validators_after_create (list, optional): List of functions that validates an event triggered when a new file
            is created. Each function must accept a param to receive the event to be validated. Default `None`
        validators_after_update (list, optional): List of functions that validates an event triggered when a new file
            is modified. Each function must accept a param to receive the event to be validated. Default `None`
        validators_after_delete (list, optional): List of functions that validates an event triggered when a new file
            is deleted. Each function must accept a param to receive the event to be validated. Default `None`
        validators_after_cud (list, optional): List of functions that validates an event triggered when a new file
            is created, modified or deleted. Each function must accept a param to receive
            the event to be validated. Default `None`
        event_mode (str, optional): Specifies the FIM scan mode to check in the events
    """

    # Transform file list
    if not isinstance(file_list, list) and not isinstance(file_list, dict):
        raise ValueError('Value error. It can only be list or dict')
    elif isinstance(file_list, list):
        file_list = {i: '' for i in file_list}

    custom_validator = CustomValidator(validators_after_create, validators_after_update,
                                       validators_after_delete, validators_after_cud)
    event_checker = EventChecker(log_monitor=log_monitor, folder=folder, file_list=file_list, options=options,
                                 custom_validator=custom_validator, encoding=encoding,
                                 callback=ev.callback_detect_file_added_event)

    # Create text files
    for name, content in file_list.items():
        create_file(REGULAR, folder, name, content=content)

    event_checker.fetch_and_check('added', min_timeout=min_timeout, triggers_event=triggers_event,
                                  event_mode=event_mode, escaped=escaped)
    if triggers_event:
        logger.info("'added' {} detected as expected.\n".format("events" if len(file_list) > 1 else "event"))

    # Modify previous text files
    if triggers_modified_event:
        for name, content in file_list.items():
            modify_file_content(folder, name, is_binary=isinstance(content, bytes))
    
        event_checker = EventChecker(log_monitor=log_monitor, folder=folder, file_list=file_list, options=options,
                                     custom_validator=custom_validator, encoding=encoding,
                                     callback=ev.callback_detect_file_modified_event)
        event_checker.fetch_and_check('modified', min_timeout=min_timeout, triggers_event=triggers_event,
                                      event_mode=event_mode, escaped=escaped)
        if triggers_event:
            logger.info("'modified' {} detected as expected.\n".format("events" if len(file_list) > 1 else "event"))

    # Delete previous text files
    for name in file_list:
        delete_file(os.path.join(folder, name))

    event_checker = EventChecker(log_monitor=log_monitor, folder=folder, file_list=file_list, options=options,
                                 custom_validator=custom_validator, encoding=encoding,
                                 callback=ev.callback_detect_file_deleted_event)
    event_checker.fetch_and_check('deleted', min_timeout=min_timeout, triggers_event=triggers_event,
                                  event_mode=event_mode, escaped=escaped)
    if triggers_event:
        logger.info("'deleted' {} detected as expected.\n".format("events" if len(file_list) > 1 else "event"))


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
            monitor.start(timeout=timeout, callback=ev.callback_detect_end_scan,
                          update_position=False,
                          error_message=f"End of scheduled scan not detected after {timeout} seconds")


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
            monitor.start(timeout=timeout, callback=ev.callback_detect_end_scan,
                          update_position=False,
                          error_message=f"End of scheduled scan not detected after {timeout} seconds")
