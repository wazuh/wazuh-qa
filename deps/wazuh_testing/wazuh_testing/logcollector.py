import os
import shutil
import sys
from os import path
from math import ceil
from json import load
from time import sleep
from datetime import datetime, timedelta

from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE, monitoring

GENERIC_CALLBACK_ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
GENERIC_CALLBACK_ERROR_INVALID_LOCATION = 'The expected invalid location error log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_FILE = 'The expected analyzing file log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL = "The expected analyzing eventchannel log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET = "The expected target socket log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET_NOT_FOUND = "The expected target socket not found error has not been produced"
LOG_COLLECTOR_GLOBAL_TIMEOUT = 20

if sys.platform == 'win32':
    prefix = monitoring.AGENT_DETECTOR_PREFIX
else:
    prefix = monitoring.LOG_COLLECTOR_DETECTOR_PREFIX


def callback_analyzing_file(file):
    """Create a callback to detect if logcollector is monitoring a file.

    Args:
        file (str): Name with absolute path of the analyzed file.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_monitoring_command(log_format, command):
    """Create a callback to detect if logcollector is monitoring a command.

    Args:
        log_format (str): Log format of the command monitoring (full_command or command).
        command (str): Monitored command.

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = 'full output' if log_format == 'full_command' else 'output'
    msg = fr"INFO: Monitoring {log_format_message} of command\(\d+\): {command}"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_monitoring_djb_multilog(program_name, multilog_file):
    """Create a callback to detect if logcollector is monitoring a djb multilog file.

    Args:
        program_name (str): Program name of multilog file.
        multilog_file (str): Multilog file name.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"INFO: Using program name '{program_name}' for DJB multilog file: '{multilog_file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_command_alias_output(alias):
    """Create a callback to detect if logcollector is monitoring a command with an assigned alias.

    Args:
        alias (str): Command alias.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Reading command message: 'ossec: output: '{alias}':"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_eventchannel_bad_format(event_location):
    """Create a callback to detect if logcollector inform about bad formatted eventchannel location.

    Args:
        event_location (str): Eventchannel location.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: Could not EvtSubscribe() for ({event_location}) which returned \(\d+\)"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_socket_target(location, socket_name):
    """Create a callback to detect if logcollector has assign a socket to a monitored file.

    Args:
        location (str): Name with the analyzed file.
        socket_name (str): Socket name.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"DEBUG: Socket target for '{location}' -> {socket_name}"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_socket_not_defined(location, socket_name):
    """Create a callback to detect if a socket has not been defined.

    Args:
        location (str): Name with the analyzed file.
        socket_name (str): Socket name.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"CRITICAL: Socket '{socket_name}' for '{location}' is not defined."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_socket_connected(socket_name, socket_path):
    """Create a callback to detect if logcollector has been connected to the specified socket.

    Args:
        socket_name (str): Socket name.
        socket_path (str): Path to UNIX named socket.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"DEBUG: Connected to socket '{socket_name}' ({socket_path})"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_log_target_not_found(location, socket_name):
    """Create a callback to detect if a log target has not been found.

    Args:
        location (str): Name with the analyzed file.
        socket_name (str): Socket name.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"WARNING: Log target '{socket_name}' not found for the output format of localfile '{location}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_invalid_reconnection_time(severity='WARNING', default_value='5'):
    """Create a callback to detect if a invalid reconnection has been used.

    Args:
        severity (str): Severity of the error (WARNING, ERROR or CRITICAL)
        default_value (int): Default value used instead of specified reconnection time.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: Invalid reconnection time value. Changed to {default_value} seconds."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_eventchannel_analyzing(event_location):
    """Create a callback to detect if logcollector is monitoring a event log.

    Args:
        event_location (str): Event log location.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"INFO: \(\d+\): Analyzing event log: '{event_location}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_invalid_location_pattern(location):
    """Create a callback to detect if invalid location pattern has been used.

    Args:
        location (str): Location pattern

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Glob error. Invalid pattern: '{location}' or no files found."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_ignoring_file(location_file):
    """Create a callback to detect if specified file was ignored due to modification time.

    Args:
        location_file: File absolute path.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"DEBUG: Ignoring file '{location_file}' due to modification time"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_reading_syslog_message(message):
    """Create a callback to detect if syslog message has been read.

    Args:
        message (str): Syslog message.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"DEBUG: Reading syslog message: '{message}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_read_line_from_file(n_lines, filename):
    """Create a callback to detect if specified lines number has been read.

    Args:
        n_lines (str): Number of lines read.
        filename (str): Filename from which lines have been read.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"DEBUG: Read {n_lines} lines from {filename}"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_read_lines(command, escape=False):
    """Create a callback to detect "DEBUG: Read <number> lines from command <command>" debug line.

    Args:
        command (str): Command to be monitored.
        escape (bool): Flag to escape special characters in the pattern.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"lines from command '{command}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=escape)


def callback_running_command(log_format, command, escape=False):
    """Create a callback to detect "DEBUG: Running <log_format> '<command>'" debug line.

    Args:
        log_format (str): Log format of the command monitoring (full_command or command).
        command (str): Command to be monitored.
        escape (bool): Flag to escape special characters in the pattern.

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = 'full command' if log_format == 'full_command' else 'command'
    msg = fr"DEBUG: Running {log_format_message} '{command}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=escape)


def callback_event_log_service_down(location, severity='WARNING'):
    """Create a callback to detect if eventlog service is down.

    Args:
        location (str): Event channel.
        severity (str): Severity of the error (WARNING, ERROR or CRITICAL).

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = f"{severity}: The eventlog service is down. Unable to collect logs from '{location}' channel."
    return monitoring.make_callback(pattern=log_format_message, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_trying_to_reconnect(location, reconnect_time):
    """Create a callback to detect if `wazuh-agentd` is trying to reconnect to specified channel.

    Args:
        location (str): Event log channel.
        reconnect_time (str): Reconnect time.

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = f"DEBUG: Trying to reconnect {location} channel in {reconnect_time} seconds."
    return monitoring.make_callback(pattern=log_format_message, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_reconnect_eventchannel(location):
    """Create a callback to detect if specified channel has been reconnected successfully.

    Args:
        location (str): Location channel.

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = f"INFO: '{location}' channel has been reconnected succesfully."
    return monitoring.make_callback(pattern=log_format_message, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_match_pattern_file(file_pattern, file):
    """Create a callback to detect if logcollector is monitoring a file with wildcard.
    Args:
        file_pattern (str): Location pattern.
        file (str): Name with absolute path of the analyzed file.
    Returns:
        callable: callback to detect this event.
    """
    msg = fr"New file that matches the '{file_pattern}' pattern: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_non_existent_file(file):
    """Create a callback to detect if logcollector is showing an error when the file does not exist.
    Args:
        file (str): Name with absolute path of the analyzed file.
    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: (1103): Could not open file '{file}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_duplicated_file(file):
    """Create a callback to detect if logcollector configuration is duplicated.
    Args:
        file (str): Name with absolute path of the analyzed file.
    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Log file '{file}' is duplicated."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_file_limit():
    """Create a callback to detect if logcollector is monitoring a file.
    Returns:
        callable: callback to detect this event.
    """
    msg = f'File limit has been reached'
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_excluded_file(file):
    """Create a callback to detect if logcollector is excluding files.
    Args:
        file (str): Name with absolute path of the analyzed file.
    Returns:
        callable: callback to detect this event.
    """
    msg = fr"File excluded: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def add_log_data(log_path, log_line_message, size_kib=1024, line_start=1, print_line_num=False):
    """Increase the space occupied by a log file by adding lines to it.

    Args:
        log_path (str): Path to log file.
        log_line_message (str): Line content to be added to the log.
        size_kib (int, optional): Size in kibibytes (1024^2 bytes). Defaults to 1 MiB (1024 KiB).
        line_start (int, optional): Line number to start with. Defaults to 1.
        print_line_num (bool, optional): If True, in each line of the log its number is added. Defaults to False.

    Returns:
        int: Last line number written.
    """
    if len(log_line_message):
        with open(log_path, 'a') as f:
            lines = ceil((size_kib * 1024) / len(log_line_message))
            for x in range(line_start, line_start + lines + 1):
                f.write(f"{log_line_message}{x}\n") if print_line_num else f.write(f"{log_line_message}\n")
        return line_start + lines - 1
    return 0


def get_data_sending_stats(log_path, socket_name, state_interval):
    """Returns the statistics of a log monitored by logcollector.

    For this purpose, it parses the "wazuh-logcollector.state" file and retrieves the data.
    See:
    https://documentation-dev.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html

    Args:
        log_path (str): Path of the log from which the statistics are to be obtained.
        socket_name (str): Target socket name.
        state_interval (int): Statistics generation interval, in seconds ("logcollector.state_interval").

    Returns:
        dict: Dictionary with the statistics.
    """
    # Wait until the statistics file becomes available
    for _ in range(state_interval * 2):
        if path.isfile(LOGCOLLECTOR_STATISTICS_FILE):
            break
        else:
            sleep(1)

    if not path.isfile(LOGCOLLECTOR_STATISTICS_FILE):
        raise TimeoutError

    with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as json_file:
        data = load(json_file)
        global_files = data['global']['files']
        global_start_date = datetime.strptime(data['global']['start'], '%Y-%m-%d %H:%M:%S')
        global_end_date = datetime.strptime(data['global']['end'], '%Y-%m-%d %H:%M:%S')
        interval_files = data['interval']['files']
        interval_start_date = datetime.strptime(data['interval']['start'], '%Y-%m-%d %H:%M:%S')
        interval_end_date = datetime.strptime(data['interval']['end'], '%Y-%m-%d %H:%M:%S')
        stats = {'global_events': 0, 'global_drops': 0,
                 'global_start_date': global_start_date, 'global_end_date': global_end_date,
                 'interval_events': 0, 'interval_drops': 0,
                 'interval_start_date': interval_start_date, 'interval_end_date': interval_end_date}
        # Global statistics
        for g_file in global_files:
            if g_file['location'] == log_path:
                stats['global_events'] = g_file['events']
                targets = g_file['targets']
                for t in targets:
                    if t['name'] == socket_name:
                        stats['global_drops'] = t['drops']
        # Interval statistics
        for i_file in interval_files:
            if i_file['location'] == log_path:
                stats['interval_events'] = i_file['events']
                targets = i_file['targets']
                for t in targets:
                    if t['name'] == socket_name:
                        stats['interval_drops'] = t['drops']
    return stats


def get_next_stats(current_stats, log_path, socket_name, state_interval):
    """Return the next statistics to be written to the "wazuh-logcollector.state" file and the seconds elapsed.

    Args:
        current_stats (dict): Dictionary with the current statistics.
        log_path (str): Path of the log from which the statistics are to be obtained.
        socket_name (str): Target socket name.
        state_interval (int): Statistics generation interval, in seconds ("logcollector.state_interval").

    Returns:
        (dict, float): A tuple with a dictionary with the next statistics and the seconds
                       elapsed between the two statistics based on the modification date
                       of the "wazuh-logcollector.state" file.

    Raises:
          TimeoutError: If the next statistics could not be obtained according to the interval
                        defined by "logcollector.state_interval"
    """
    mtime_current = path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
    next_interval_date = current_stats['interval_end_date'] + timedelta(seconds=state_interval)
    next_2_intervals_date = current_stats['interval_end_date'] + timedelta(seconds=state_interval * 2)
    for _ in range(0, state_interval * 2):
        stats = get_data_sending_stats(log_path, socket_name, state_interval)
        mtime_next = path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
        # The time of the interval must be equal to or greater than the calculated time,
        # but less than the calculated time for two intervals.
        if next_interval_date <= stats['interval_end_date'] < next_2_intervals_date:
            return stats, mtime_next - mtime_current
        else:
            sleep(1)
    raise TimeoutError


def create_file_structure(get_files_list):
    """Create the specified file tree structure.

    Args:
        get_files_list(dict):  Files to create.
    """
    for file in get_files_list:
        os.makedirs(file['folder_path'], exist_ok=True, mode=0o777)
        for name in file['filename']:
            open(os.path.join(file['folder_path'], name), 'w').close()

            if 'age' in file:
                fileinfo = os.stat(f"{file['folder_path']}{file['filename']}")
                os.utime(f"{file['folder_path']}{file['filename']}", (fileinfo.st_atime - file['age'],
                                                                      fileinfo.st_mtime - file['age']))
            elif 'size' in file:
                add_log_data(log_path=os.path.join(file['folder_path'], name),
                             log_line_message=file['content'], size_kib=file['size_kib'])


def delete_file_structure(get_files_list):
    """Delete the specified file tree structure.

    Args:
        get_files_list(dict):  Files to delete.
    """
    for file in get_files_list:
        shutil.rmtree(file['folder_path'], ignore_errors=True)
