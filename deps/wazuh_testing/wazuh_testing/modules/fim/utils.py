# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

from datetime import datetime, timedelta
from typing import Sequence, Union, Generator, Any
from copy import deepcopy
from wazuh_testing import global_parameters, logger, REGULAR
from wazuh_testing.tools.file import create_file, modify_file, delete_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.time import TimeMachine
from wazuh_testing.modules import fim
from wazuh_testing.modules.fim.event_monitor import (callback_detect_end_scan, callback_detect_file_added_event,
                                                     callback_detect_file_modified_event,
                                                     callback_detect_file_deleted_event)
from wazuh_testing.modules.fim.classes import CustomValidator, EventChecker


if sys.platform == 'win32':
    import win32con
    import win32api
    import pywintypes


# Variables
_os_excluded_from_rt_wd = ['darwin', 'sunos5']
_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Functions
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
            logger.info("Creating registry key " + str(os.path.join(fim.registry_class_name[key], subkey)))

            key = win32api.RegCreateKeyEx(key, subkey, win32con.KEY_ALL_ACCESS | arch)

            return key[0]  # Ignore the flag that RegCreateKeyEx returns
        except OSError as e:
            logger.warning(f"Registry could not be created: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry could not be created: {e}")


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


def regular_file_cud(folder, log_monitor, file_list=['testfile0'], time_travel=False, min_timeout=1, options=None,
                     triggers_event=True, encoding=None, callback=callback_detect_file_added_event,
                     validators_after_create=None, validators_after_update=None, validators_after_delete=None,
                     validators_after_cud=None, event_mode=None):
    """Check if creation, update and delete events are detected by syscheck.

    This function provides multiple tools to validate events with custom validators.

    Args:
        folder (str): Path where the files will be created.
        log_monitor (FileMonitor): File event monitor.
        file_list (list(str) or dict, optional): If it is a list, it will be transformed to a dict with
            empty strings in each value. Default `['testfile0']`
        time_travel (boolean, optional): Boolean to determine if there will be time travels or not. Default `False`
        min_timeout (int, optional): Minimum timeout. Default `1`
        options (set, optional): Set with all the checkers. Default `None`
        triggers_event (boolean, optional): Boolean to determine if the event should be raised or not. Default `True`
        encoding (str, optional): String to determine the encoding of the file name. Default `None`
        callback (callable, optional): Callback to use with the log monitor. Default `callback_detect_event`
        validators_after_create (list, optional): List of functions that validates an event triggered when a new file
            is created. Each function must accept a param to receive the event to be validated. Default `None`
        validators_after_update (list, optional): List of functions that validates an event triggered when a new file
            is modified. Each function must accept a param to receive the event to be validated. Default `None`
        validators_after_delete (list, optional): List of functions that validates an event triggered when a new file
            is deleted. Each function must accept a param to receive the event to be validated. Default `None`
        validators_after_cud (list, optional): List of functions that validates an event triggered when a new file
            is created, modified or deleted. Each function must accept a param to receive
            the event to be validated. Default `None`
        event_mode (str, optional): Specifie2 unidadess the FIM scan mode to check in the events
    """

    # Transform file list
    if not isinstance(file_list, list) and not isinstance(file_list, dict):
        raise ValueError('Value error. It can only be list or dict')
    elif isinstance(file_list, list):
        file_list = {i: '' for i in file_list}

    custom_validator = CustomValidator(validators_after_create, validators_after_update,
                                       validators_after_delete, validators_after_cud)
    event_checker = EventChecker(log_monitor=log_monitor, folder=folder, file_list=file_list, options=options,
                                 custom_validator=custom_validator, encoding=encoding, callback=callback)

    # Create text files
    for name, content in file_list.items():
        create_file(REGULAR, folder, name, content=content)

    check_time_travel(time_travel, monitor=log_monitor)

    event_checker.fetch_and_check('added', min_timeout=min_timeout, triggers_event=triggers_event,
                                  event_mode=event_mode)
    if triggers_event:
        logger.info("'added' {} detected as expected.\n".format("events" if len(file_list) > 1 else "event"))

        if time_travel:
            log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                              update_position=True,
                              error_message=f"End of scheduled scan not detected after "
                              f"{global_parameters.default_timeout} seconds")

    # Modify previous text files
    for name, content in file_list.items():
        modify_file(folder, name, is_binary=isinstance(content, bytes))

    check_time_travel(time_travel, monitor=log_monitor)
    event_checker = EventChecker(log_monitor=log_monitor, folder=folder, file_list=file_list, options=options,
                                 custom_validator=custom_validator, encoding=encoding,
                                 callback=callback_detect_file_modified_event)
    event_checker.fetch_and_check('modified', min_timeout=min_timeout, triggers_event=triggers_event,
                                  event_mode=event_mode)
    if triggers_event:
        logger.info("'modified' {} detected as expected.\n".format("events" if len(file_list) > 1 else "event"))

        if time_travel:
            log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                              update_position=True,
                              error_message=f"End of scheduled scan not detected after "
                              f"{global_parameters.default_timeout} seconds")

    # Delete previous text files
    for name in file_list:
        delete_file(os.path.join(folder, name))

    check_time_travel(time_travel, monitor=log_monitor)
    event_checker = EventChecker(log_monitor=log_monitor, folder=folder, file_list=file_list, options=options,
                                 custom_validator=custom_validator, encoding=encoding,
                                 callback=callback_detect_file_deleted_event)
    event_checker.fetch_and_check('deleted', min_timeout=min_timeout, triggers_event=triggers_event,
                                  event_mode=event_mode)
    if triggers_event:
        logger.info("'deleted' {} detected as expected.\n".format("events" if len(file_list) > 1 else "event"))

        if time_travel:
            log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_end_scan,
                              update_position=True,
                              error_message=f"End of scheduled scan not detected after "
                              f"{global_parameters.default_timeout} seconds")


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
