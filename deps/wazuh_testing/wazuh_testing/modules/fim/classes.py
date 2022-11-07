# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import subprocess
import json
from collections import Counter
from wazuh_testing import global_parameters, logger
from wazuh_testing.modules.fim.event_monitor import callback_detect_event
from wazuh_testing.modules.fim.utils import validate_event

if sys.platform == 'linux2' or sys.platform == 'linux':
    from jq import jq


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


class EventChecker:
    """Utility to allow fetch events and validate them."""

    def __init__(self, log_monitor, folder, file_list=['testfile0'], options=None, custom_validator=None, encoding=None,
                 callback=callback_detect_event):
        self.log_monitor = log_monitor
        self.folder = folder
        self.file_list = file_list
        self.custom_validator = custom_validator
        self.options = options
        self.encoding = encoding
        self.events = None
        self.callback = callback

    def fetch_and_check(self, event_type, min_timeout=1, triggers_event=True, extra_timeout=0, event_mode=None):
        """Call both 'fetch_events' and 'check_events'.

        Args:
            event_type (str): Expected type of the raised event {'added', 'modified', 'deleted'}.
            event_mode (str, optional): Specifies the scan mode to check in the events
            min_timeout (int, optional): seconds to wait until an event is raised when trying to fetch. Defaults `1`
            triggers_event (boolean, optional): True if the event should be raised. False otherwise. Defaults `True`
            extra_timeout (int, optional): Additional time to wait after the min_timeout
        """
        num_files = len(self.file_list)
        error_msg = "TimeoutError was raised because "
        error_msg += str(num_files) if num_files > 1 else "a single"
        error_msg += " '" + str(event_type) + "' "
        error_msg += "events were " if num_files > 1 else "event was "
        error_msg += "expected for " + str(self._get_file_list())
        error_msg += " but were not detected." if len(self.file_list) > 1 else " but was not detected."

        self.events = self.fetch_events(min_timeout, triggers_event, extra_timeout, error_message=error_msg)
        self.check_events(event_type, mode=event_mode)

    def fetch_events(self, min_timeout=1, triggers_event=True, extra_timeout=0, error_message=''):
        """Try to fetch events on a given log monitor. Will return a list with the events detected.

        Args:
            min_timeout (int, optional): seconds to wait until an event is raised when trying to fetch. Defaults `1`
            triggers_event (boolean, optional): True if the event should be raised. False otherwise. Defaults `True`
            extra_timeout (int, optional): Additional time to wait after the min_timeout
            error_message (str): Message to explain a possible timeout error
        """

        def clean_results(event_list):
            """Iterate the event_list provided and check if the 'modified' events contained should be merged to fix
            whodata's bug that raise more than one modification event when a file is modified. If some 'modified' event
            shares 'path' and 'timestamp' we assume that belongs to the same modification.
            """
            if not isinstance(event_list, list):
                return event_list
            result_list = list()
            previous = None
            while len(event_list) > 0:
                current = event_list.pop(0)
                if current['data']['type'] == "modified":
                    if not previous:
                        previous = current
                    elif (previous['data']['path'] == current['data']['path'] and
                          current['data']['timestamp'] in [previous['data']['timestamp'],
                                                           previous['data']['timestamp'] + 1]):
                        previous['data']['changed_attributes'] = list(set(previous['data']['changed_attributes']
                                                                          + current['data']['changed_attributes']))
                        previous['data']['attributes'] = current['data']['attributes']
                    else:
                        result_list.append(previous)
                        previous = current
                else:
                    result_list.append(current)
            if previous:
                result_list.append(previous)
            return result_list

        try:
            result = self.log_monitor.start(timeout=max(len(self.file_list) * 0.01, min_timeout),
                                            callback=self.callback,
                                            accum_results=len(self.file_list),
                                            timeout_extra=extra_timeout,
                                            encoding=self.encoding,
                                            error_message=error_message).result()
            assert triggers_event, f'No events should be detected.'
            if extra_timeout > 0:
                result = clean_results(result)
            return result if isinstance(result, list) else [result]
        except TimeoutError:
            if triggers_event:
                raise
            logger.info("TimeoutError was expected and correctly caught.")

    def check_events(self, event_type, mode=None):
        """Check and validate all events in the 'events' list.

        Args:
            event_type (str): Expected type of the raised event {'added', 'modified', 'deleted'}.
            mode (str, optional): Specifies the FIM scan mode to check in the events
        """

        def validate_checkers_per_event(events, options, mode):
            """Check if each event is properly formatted according to some checks.

            Args:
                events (list): event list to be checked.
                options (set): set of XML CHECK_* options. Default `{CHECK_ALL}`
                mode (str): represents the FIM mode expected for the event to validate.
            """
            for ev in events:
                validate_event(ev, options, mode)

        def check_events_type(events, ev_type, file_list=['testfile0']):
            event_types = Counter(filter_events(events, ".[].data.type"))
            msg = f"Non expected number of events. {event_types[ev_type]} != {len(file_list)}"
            assert (event_types[ev_type] == len(file_list)), msg

        def check_events_path(events, folder, file_list=['testfile0'], mode=None):
            mode = global_parameters.current_configuration['metadata']['fim_mode'] if mode is None else mode
            data_path = filter_events(events, ".[].data.path")
            for file_name in file_list:
                expected_path = os.path.join(folder, file_name)
                if self.encoding is not None:
                    for index, item in enumerate(data_path):
                        data_path[index] = item.encode(encoding=self.encoding)
                if sys.platform == 'darwin' and self.encoding and self.encoding != 'utf-8':
                    logger.info(f"Not asserting {expected_path} in event.data.path. "
                                f'Reason: using non-utf-8 encoding in darwin.')
                else:
                    error_msg = f"Expected data path was '{expected_path}' but event data path is '{data_path}'"
                    assert (expected_path in data_path), error_msg

        def filter_events(events, mask):
            """Returns a list of elements matching a specified mask in the events list using jq module."""
            if sys.platform in ("win32", 'sunos5', 'darwin'):
                stdout = subprocess.check_output(["jq", "-r", mask], input=json.dumps(events).encode())
                return stdout.decode("utf8").strip().split(os.linesep)
            else:
                return jq(mask).transform(events, multiple_output=True)

        if self.events is not None:
            validate_checkers_per_event(self.events, self.options, mode)
            check_events_type(self.events, event_type, self.file_list)
            check_events_path(self.events, self.folder, file_list=self.file_list, mode=mode)

            if self.custom_validator is not None:
                self.custom_validator.validate_after_cud(self.events)
                if event_type == "added":
                    self.custom_validator.validate_after_create(self.events)
                elif event_type == "modified":
                    self.custom_validator.validate_after_update(self.events)
                elif event_type == "deleted":
                    self.custom_validator.validate_after_delete(self.events)

    def _get_file_list(self):
        result_list = []
        for file_name in self.file_list:
            expected_file_path = os.path.join(self.folder, file_name)
            expected_file_path = expected_file_path[:1].lower() + expected_file_path[1:]
            result_list.append(expected_file_path)
        return result_list
