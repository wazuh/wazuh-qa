# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json

from sys import platform
from datetime import datetime
from wazuh_testing import LOG_FILE_PATH, logger, T_60, T_30
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback


# Variables
file_monitor = FileMonitor(LOG_FILE_PATH)


# Callbacks messages
CB_DETECT_FIM_EVENT = r".*Sending FIM event: (.+)$"
CB_FOLDERS_MONITORED_REALTIME = r'.*Folders monitored with real-time engine: (\d+)'
CB_INVALID_CONFIG_VALUE = r".*Invalid value for element '(.*)': (.*)."
CB_INTEGRITY_CONTROL_MESSAGE = r".*Sending integrity control message: (.+)$"
CB_MAXIMUM_FILE_SIZE = r'.*Maximum file size limit to generate diff information configured to \'(\d+) KB\'.*'
CB_AGENT_CONNECT = r'.* Connected to the server .*'
CB_INODE_ENTRIES_PATH_COUNT = r".*Fim inode entries: '(\d+)', path count: '(\d+)'"
CB_DATABASE_FULL_COULD_NOT_INSERT_VALUE = r".*registry_value.*Couldn't insert ('.*') entry into DB. The DB is full.*"
CB_DATABASE_FULL_COULD_NOT_INSERT_KEY = r".*registry_key.*Couldn't insert ('.*') entry into DB. The DB is full.*"
CB_COUNT_REGISTRY_ENTRIES = r".*Fim registry entries count: '(\d+)'"
CB_COUNT_REGISTRY_VALUE_ENTRIES = r".*Fim registry values entries count: '(\d+)'"
CB_REGISTRY_DBSYNC_NO_DATA = r".*fim_registry_(.*) dbsync no_data (.*)'"
CB_REGISTRY_LIMIT_CAPACITY = r".*Registry database is (\d+)% full."
CB_REGISTRY_DB_BACK_TO_NORMAL = r".*(The registry database status returns to normal)."
CB_REGISTRY_LIMIT_VALUE = r".*Maximum number of registry values to be monitored: '(\d+)'"
CB_FILE_LIMIT_CAPACITY = r".*File database is (\d+)% full."
CB_FILE_LIMIT_BACK_TO_NORMAL = r".*(Sending DB back to normal alert)."
CB_FIM_ENTRIES_COUNT = r".*Fim file entries count: '(\d+)'"
CB_FILE_LIMIT_VALUE = r".*Maximum number of files to be monitored: '(\d+)'"
CB_FILE_LIMIT_DISABLED = r".*(No limit set) to maximum number of file entries to be monitored"
CB_PATH_MONITORED_REALTIME = r".*Directory added for real time monitoring: (.*)"
CB_PATH_MONITORED_WHODATA = r".*Added audit rule for monitoring directory: (.*)"
CB_PATH_MONITORED_WHODATA_WINDOWS = r".*Setting up SACL for (.*)"
CB_SYNC_SKIPPED = r".*Sync still in progress. Skipped next sync and increased interval.*'(\d+)s'"
CB_SYNC_INTERVAL_RESET = r".*Previous sync was successful. Sync interval is reset to: '(\d+)s'"
CB_IGNORING_DUE_TO_SREGEX = r".*?Ignoring path '(.*)' due to sregex '(.*)'.*"
CB_IGNORING_DUE_TO_PATTERN = r".*?Ignoring path '(.*)' due to pattern '(.*)'.*"
CB_REALTIME_WHODATA_ENGINE_STARTED = r'.*File integrity monitoring (real-time Whodata) engine started.*'
CB_DISK_QUOTA_LIMIT_CONFIGURED_VALUE = r'.*Maximum disk quota size limit configured to \'(\d+) KB\'.*'
CB_FILE_EXCEEDS_DISK_QUOTA = r'.*The (.*) of the file size \'(.*)\' exceeds the disk_quota.*'
CB_FILE_SIZE_LIMIT_REACHED = r'.*File \'(.*)\' is too big for configured maximum size to perform diff operation\.'
CB_DIFF_FOLDER_DELETED = r'.*Folder \'(.*)\' has been deleted.*'
CB_FIM_PATH_CONVERTED = r".*fim_adjust_path.*Convert '(.*) to '(.*)' to process the FIM events."
CB_STARTING_WINDOWS_AUDIT = r'.*state_checker.*(Starting check of Windows Audit Policies and SACLs)'
CB_FIM_WILDCARD_EXPANDING = r".*Expanding entry '.*' to '(.*)' to monitor FIM events."
CB_SWITCHING_DIRECTORIES_TO_REALTIME = r'.*state_checker.*(Audit policy change detected.\
                                         Switching directories to realtime)'
CB_RECIEVED_EVENT_4719 = r'.*win_whodata.*(Event 4719).*Switching directories to realtime'
CB_FIM_REGISTRY_ENTRIES_COUNT = r".*Fim registry entries count: '(.*)'"
CB_FIM_REGISTRY_VALUES_ENTRIES_COUNT = r".*Fim registry values entries count: '(.*)'"


# Error message
ERR_MSG_REALTIME_FOLDERS_EVENT = 'Did not receive expected "Folders monitored with real-time engine" event'
ERR_MSG_WHODATA_ENGINE_EVENT = 'Did not receive expected "real-time Whodata engine started" event'
ERR_MSG_INVALID_CONFIG_VALUE = 'Did not receive expected "Invalid value for element" event'
ERR_MSG_AGENT_DISCONNECT = 'Agent couldn\'t connect to server.'
ERR_MSG_INTEGRITY_CONTROL_MSG = 'Didn\'t receive control message(integrity_check_global)'
ERR_MSG_DATABASE_PERCENTAGE_FULL_ALERT = 'Did not receive expected "DEBUG: ...: database is ...% full" alert'
ERR_MSG_WRONG_CAPACITY_LOG_DB_LIMIT = 'Wrong capacity log for DB file_limit'
ERR_MSG_DB_BACK_TO_NORMAL = 'Did not receive expected "DEBUG: ... database status returns to normal." event'
ERR_MSG_DATABASE_FULL_ALERT = 'Did not receive expected "DEBUG: ...: Registry database is 100% full" alert'
ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL = 'Wrong value for full database alert.'
ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT = 'Did not receive expected "DEBUG: ...: Couldn\'t insert \'...\' entry \
                                          into DB. The DB is full, ..." event'
ERR_MSG_DATABASE_FULL_ALERT_EVENT = 'Did not receive expected "DEBUG: ...: Sending DB 100% full alert." event'
ERR_MSG_WRONG_NUMBER_OF_ENTRIES = 'Wrong number of entries counted.'
ERR_MSG_WRONG_INODE_PATH_COUNT = 'Wrong number of inodes and path count'
ERR_MSG_FIM_INODE_ENTRIES = 'Did not receive expected "Fim inode entries: ..., path count: ..." event'
ERR_MSG_FIM_REGISTRY_ENTRIES = 'Did not receive expected "Fim Registry entries count: ..." event'
ERR_MSG_FIM_REGISTRY_VALUE_ENTRIES = 'Did not receive expected "Fim Registry value entries count: ..." event'
ERR_MSG_REGISTRY_LIMIT_VALUES = 'Did not receive expected "DEBUG: ...: Maximum number of registry values to \
                                 be monitored: ..." event'
ERR_MSG_WRONG_REGISTRY_LIMIT_VALUE = 'Wrong value for db_value_limit registries tag.'
ERR_MSG_FILE_LIMIT_VALUES = 'Did not receive expected "DEBUG: ...: Maximum number of files to be monitored:..." event'
ERR_MSG_WRONG_FILE_LIMIT_VALUE = 'Wrong value for file_limit.'
ERR_MSG_FILE_LIMIT_DISABLED = 'Did not receive expected "DEBUG: ...: No limit set to maximum number of entries \
                               to be monitored" event'
ERR_MSG_MAXIMUM_FILE_SIZE = 'Did not receive expected "Maximum file size limit configured to \'... KB\'..." event'
ERR_MSG_NO_EVENTS_EXPECTED = 'No events should be detected.'
ERR_MSG_DELETED_EVENT_NOT_RECIEVED = 'Did not receive expected deleted event'
ERR_MSG_FIM_EVENT_NOT_RECIEVED = 'Did not receive expected "Sending FIM event: ..." event'
ERR_MSG_MONITORING_PATH = 'Did not get the expected monitoring path line'
ERR_MSG_MULTIPLE_FILES_CREATION = 'Multiple files could not be created.'
ERR_MSG_SCHEDULED_SCAN_ENDED = 'Did not recieve the expected  "DEBUG: ... Sending FIM event: {type:scan_end"...} event'
ERR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE = 'Wrong value for diff_size_limit'
ERR_MSG_INTEGRITY_OR_WHODATA_NOT_STARTED = 'Did not receive expected "File integrity monitoring real-time Whodata \
                                            engine started" or "Initializing FIM Integrity Synchronization check"'
ERR_MSG_INTEGRITY_CHECK_EVENT = 'Did not receive expected "Initializing FIM Integrity Synchronization check" event'
ERR_MSG_SYNC_SKIPPED_EVENT = 'Did not recieve the expected "Sync still in progress. Skipped next sync" event'
ERR_MSG_FIM_SYNC_NOT_DETECTED = 'Did not receive expected "Initializing FIM Integrity Synchronization check" event'
ERR_MSG_SYNC_INTERVAL_RESET_EVENT = 'Did not recieve the expected "Sync interval is reset" event'
ERR_MSG_CONTENT_CHANGES_EMPTY = "content_changes is empty"
ERR_MSG_CONTENT_CHANGES_NOT_EMPTY = "content_changes isn't empty"
ERR_MSG_FOLDERS_MONITORED_REALTIME = 'Did not receive expected "Folders monitored with real-time engine..." event'
ERR_MSG_WHODATA_ENGINE_EVENT = 'Did not receive "File integrity monitoring real-time Whodata engine started" event'
ERR_MSG_FIM_EVENT_NOT_DETECTED = 'Did not receive expected "Sending FIM event: ..." event.'
ERR_MSG_SCHEDULED_SCAN_STARTED = 'Did not receive expected "File integrity monitoring scan started" event'
ERR_MSG_SCHEDULED_SCAN_ENDED = 'Did not receive expected "File integrity monitoring scan ended" event'
ERR_MSG_DISK_QUOTA_LIMIT = 'Did not receive "Maximum disk quota size limit configured to \'... KB\'." event'
ERR_MSG_FILE_LIMIT_REACHED = 'Did not receive "File ... is too big ... to perform diff operation" event.'
ERR_MSG_FOLDER_DELETED = 'Did not receive expected "Folder ... has been deleted." event.'
ERR_MSG_SACL_CONFIGURED_EVENT = 'Did not receive the expected "The SACL of <file> will be configured" event'
ERR_MSG_WHODATA_REALTIME_MODE_CHANGE_EVENT = 'Expected "directory starts to monitored in real-time" event not received'


# Callback functions
def callback_detect_event(line):
    """
    Detect an 'event' type FIM log.
    """
    msg = CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event':
            return json_event
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_end_scan(line):
    """ Callback that detects if a line in a log is an end of scheduled scan event
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    match = re.match(CB_DETECT_FIM_EVENT, line)
    if not match:
        return None
    try:
        if json.loads(match.group(1))['type'] == 'scan_end':
            return True
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_scan_start(line):
    """ Callback that detects if a line in a log is the start of a scheduled scan or initial scan.
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    msg = CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_start':
            return True
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_synchronization(line):
    if 'Executing FIM sync' in line:
        return line
    return None


def callback_connection_message(line):
    match = re.match(CB_AGENT_CONNECT, line)
    if match:
        return True


def callback_detect_integrity_control_event(line):
    match = re.match(CB_INTEGRITY_CONTROL_MESSAGE, line)
    if match:
        return json.loads(match.group(1))
    return None


def callback_integrity_message(line):
    if callback_detect_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))


def callback_integrity_sync_message(line):
    """ Callback that detects if a line contains a integrity sync event
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    Returns:
        List: returns a list with formated datetime, And the event's JSON data.
    """
    if callback_detect_integrity_control_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))


def callback_detect_integrity_check_global(line):
    """ Callback that detects if a line contains an 'integrity_check_global' event
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    Returns:
        JSON: returns event's JSON data.
    """
    match = callback_detect_integrity_control_event(line)
    if match:
        if match['type'] == 'integrity_check_global':
            return match
    return None


def callback_detect_file_integrity_event(line):
    """ Callback that detects if a line contains a file integrity event

    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    event = callback_detect_integrity_control_event(line)
    if event and event['component'] == 'fim_file':
        return event
    return None


def callback_key_event(line):
    """ Callback that detects if a line contains a registry integrity event for a registry_key
    Args:
        line (String): string line to be checked by callback in File_Monitor.
    """
    event = callback_detect_event(line)
    if event is None or event['data']['attributes']['type'] != 'registry_key':
        return None

    return event


def callback_value_event(line):
    event = callback_detect_event(line)

    if event is None or event['data']['attributes']['type'] != 'registry_value':
        return None

    return event


def callback_detect_registry_integrity_event(line):
    """ Callback that detects if a line contains a registry integrity event for a registry_key or registry_value

    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    event = callback_detect_integrity_control_event(line)
    if event and event['component'] == 'fim_registry_key':
        return event
    if event and event['component'] == 'fim_registry_value':
        return event
    return None


def callback_detect_registry_integrity_state_event(line):
    """ Callback that detects if a line contains a registry integrity event of the state type

    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    event = callback_detect_registry_integrity_event(line)
    if event and event['type'] == 'state':
        return event['data']
    return None


def callback_entries_path_count(line):
    if platform != 'win32':
        match = re.match(CB_INODE_ENTRIES_PATH_COUNT, line)
    else:
        match = re.match(CB_FIM_ENTRIES_COUNT, line)

    if match:
        if platform != 'win32':
            return match.group(1), match.group(2)
        else:
            return match.group(1), None


def callback_num_inotify_watches(line):
    """ Callback that detects if a line contains the folders monitored in realtime event

    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    match = re.match(CB_FOLDERS_MONITORED_REALTIME, line)

    if match:
        return match.group(1)


def callback_sync_start_time(line):
    if callback_detect_synchronization(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S')


def callback_state_event_time(line):
    if callback_detect_integrity_control_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S')


def callback_real_time_whodata_started(line):
    """ Callback that detects if a line contains "Whodata engine started" event
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    match = re.match(CB_REALTIME_WHODATA_ENGINE_STARTED, line)
    if match:
        return True

    return None


def callback_detect_registry_integrity_clear_event(line):
    """ Callback that detects if a line contains a registry integrity_clear event

    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    event = callback_detect_integrity_control_event(line)
    if event and event['component'] == 'fim_registry_key' and event['type'] == 'integrity_clear':
        return True
    if event and event['component'] == 'fim_registry_value' and event['type'] == 'integrity_clear':
        return True
    return None


def callback_disk_quota_limit_reached(line):
    match = re.match(CB_FILE_EXCEEDS_DISK_QUOTA, line)

    if match:
        return match.group(2)


def callback_detect_file_added_event(line):
    """ Callback that detects if a line in a log is a file added event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'added':
            return json_event

    return None


def callback_detect_file_modified_event(line):
    """ Callback that detects if a line in a log is a file modified event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'modified':
            return json_event

    return None


def callback_detect_file_deleted_event(line):
    """ Callback that detects if a line in a log is a file deleted event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'deleted':
            return json_event

    return None


def callback_detect_file_more_changes(line):
    """ Callback that detects if a line in a log contains 'More changes' in content_changes.
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)
    if json_event is not None and 'content_changes' in json_event['data']:
        if 'More changes' in json_event['data']['content_changes']:
            return json_event


def callback_audit_cannot_start(line):
    """ Callback that detects if a line shows whodata engine could not start and monitoring switched to realtime.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        boolean: return True if line matches, None otherwise
    """
    match = re.match(r'.*Who-data engine could not start. Switching who-data to real-time.', line)
    if match:
        return True


def callback_restricted(line):
    """ Callback that detects if a line in a log  if a file is ignored due to configured restrict tag.

    Returns:
        string: returns path for the entry that is being ignored.
    """
    match = re.match(r".*Ignoring entry '(.*?)' due to restriction '.*?'", line)
    if match:
        return match.group(1)
    return None


# Event checkers
def check_fim_event(file_monitor=None, callback='', error_message=None, update_position=True,
                    timeout=T_60, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if a analysisd event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
                    error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=generate_monitoring_callback(callback), error_message=error_message)


def detect_initial_scan(file_monitor):
    """Detect initial scan when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=callback_detect_end_scan,
                       error_message=ERR_MSG_SCHEDULED_SCAN_ENDED)


def detect_initial_scan_start(file_monitor):
    """Detect initial scan start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=callback_detect_scan_start,
                       error_message=ERR_MSG_SCHEDULED_SCAN_STARTED)


def detect_realtime_start(file_monitor):
    """Detect realtime engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(CB_FOLDERS_MONITORED_REALTIME),
                       error_message=ERR_MSG_FOLDERS_MONITORED_REALTIME)


def detect_whodata_start(file_monitor, timeout=T_60):
    """Detect whodata engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
        timeout (int): timeout for file monitor to try to detect event
    """
    file_monitor.start(timeout=timeout, callback=generate_monitoring_callback(CB_REALTIME_WHODATA_ENGINE_STARTED),
                       error_message=ERR_MSG_WHODATA_ENGINE_EVENT)


def get_messages(callback, timeout=T_30):
    """Look for as many synchronization events as possible.
    This function will look for the synchronization messages until a Timeout is raised or 'max_events' is reached.
    Args:
        callback (str): Callback to be used to detect the event.
        timeout (int): Timeout that will be used to get the dbsync_no_data message.

    Returns:
        A list with all the events in json format.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    events = []
    for _ in range(0, MAX_EVENTS_VALUE):
        event = None
        try:
            event = wazuh_log_monitor.start(timeout=timeout, accum_results=1,
                                            callback=callback,
                                            error_message=f"Did not receive expected {callback} event").result()
        except TimeoutError:
            break
        if event is not None:
            events.append(event)
    return events


def check_registry_crud_event(callback, path,  timeout=T_30, type='added', arch='x32', value_name=None):
    """Get  all events matching the callback and validate the type, path and architecture of event
    Args:
        callback (str): Callback to be used to detect the event.
        path (str): path to be checked
        timeout (int): Timeout that will be used to try and get the expected messages
        type (str): type of event to be checked
        arch (str): architecture of the event to be checked
        value_name (str): name of the value to be checked
    """
    events = get_messages(callback=callback, timeout=timeout)
    for event in events:
        if event['data']['type'] == type and arch in event['data']['arch'] and event['data']['path'] == path:
            if value_name is not None:
                if 'value_name' in event and event['data']['value_name'] == value_name:
                    return event
            else:
                return event

    return None


def detect_windows_sacl_configured(file_monitor, file='.*'):
    """Detects when windows permision checks have been configured for a given file.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
        file: The path of the file that will be monitored
    """

    pattern = fr".*win_whodata.*The SACL of '({file})' will be configured"
    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(pattern),
                       error_message=ERR_MSG_SACL_CONFIGURED_EVENT)


def detect_windows_whodata_mode_change(file_monitor, file='.*'):
    """Detects whe monitoring for a file changes from whodata to real-time.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
        file: The path of the file that will be monitored
    """

    pattern = fr".*set_whodata_mode_changes.*The '({file})' directory starts to be monitored in real-time mode."

    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(pattern),
                       error_message=ERR_MSG_WHODATA_REALTIME_MODE_CHANGE_EVENT)


def get_fim_event(file_monitor=None, callback='', error_message=None, update_position=True,
                  timeout=T_60, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """ Check if FIM event occurs and return it according to the callback.
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
    Returns:
         returns the value given by the callback used. Default None.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
                    error_message

    result = file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                                callback=callback, error_message=error_message).result()
    return result
