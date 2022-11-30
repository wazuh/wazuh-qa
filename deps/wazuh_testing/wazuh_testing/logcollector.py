import os
import re
import shutil
import stat
import sys
from datetime import datetime, timedelta
from json import load
from math import ceil
from tempfile import gettempdir
from time import sleep

from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE, WAZUH_PATH, monitoring

GENERIC_CALLBACK_MSG_LOG_FILE_DUPLICATED = r".*Log file (.+) is duplicated."

GENERIC_CALLBACK_ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
GENERIC_CALLBACK_ERROR_INVALID_LOCATION = 'The expected invalid location error log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_FILE = 'The expected analyzing file log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL = "The expected analyzing eventchannel log has not been produced"
GENERIC_CALLBACK_ERROR_ANALYZING_MACOS = "The expected analyzing macos log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET = "The expected target socket log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET_NOT_FOUND = "The expected target socket not found error has not been produced"
GENERIC_CALLBACK_ERROR_READING_FILE = "The expected invalid content error log has not been produced"
GENERIC_CALLBACK_ERROR_LOG_FILE_DUPLICATED = "The expected warning log file duplicated has not been produced."
GENERIC_CALLBACK_ERROR = 'The expected error output has not been produced'

LOG_COLLECTOR_GLOBAL_TIMEOUT = 40

DEFAULT_AUTHD_REMOTED_SIMULATOR_CONFIGURATION = {
    'ip_address': 'localhost',
    'client_keys': os.path.join(WAZUH_PATH, 'etc', 'client.keys'),
    'server_keys': os.path.join(WAZUH_PATH, 'etc', 'sslmanager.key'),
    'server_cert': os.path.join(WAZUH_PATH, 'etc', 'sslmanager.cert'),
    'authd_port': 1515,
    'remoted_port': 1514,
    'protocol': 'tcp',
    'remoted_mode': 'CONTROLLED_ACK',
}

MACOS_LOG_COMMAND_PATH = '/usr/bin/log'

TEMPLATE_OSLOG_MESSAGE = 'Custom os_log event message'
TEMPLATE_ACTIVITY_MESSAGE = 'Custom activity event message'
TEMPLATE_TRACE_MESSAGE = 'Custom trace event message'

WINDOWS_CHANNEL_LIST = ['Microsoft-Windows-Sysmon/Operational',
                        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
                        'Application',
                        'Security',
                        'System',
                        'Microsoft-Windows-Sysmon/Operational',
                        'Microsoft-Windows-Windows Defender/Operational',
                        'File Replication Service',
                        'Service Microsoft-Windows-TerminalServices-RemoteConnectionManager'
                        ]

MAP_MACOS_TYPE_VALUE = {
    'log': 1024,
    'trace': 768,
    'activity': 513
}

MAP_MACOS_LEVEL_VALUE = {
    'debug': 0,
    'info': 1,
    'default': 2,
    'error': 3,
    'fault': 4
}

if sys.platform == 'win32':
    LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS = {
        'windows.debug': '2',
        'agent.debug': '2'
    }
    prefix = monitoring.WINDOWS_AGENT_DETECTOR_PREFIX
else:
    LOGCOLLECTOR_DEFAULT_LOCAL_INTERNAL_OPTIONS = {
        'logcollector.debug': '2',
        'monitord.rotate_log': '0',
        'agent.debug': '0',
    }
    prefix = monitoring.LOG_COLLECTOR_DETECTOR_PREFIX


def callback_missing_element_error(line):
    match = re.match(r'.* \(\d+\): Missing \'(.+)\' element.', line)
    if match:
        return True
    return None


def callback_read_macos_message(msg):
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_analyzing_file(file):
    """Create a callback to detect if logcollector is monitoring a file.
    Args:
        file (str): Name with absolute path of the analyzed file.
    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_macos_log(msg):
    """Create a callback to detect macos log.
    Args:
        msg (str): macOS message.
    Returns:
        callable: callback to detect this event.
    """
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_removed_file(file):
    """Create a callback to detect if logcollector has detected that a monitored file has been deleted.
    Args:
        file (str): Absolute path of the deleted file.
    Returns:
        callable: Callback to detect this event.
    """

    msg = fr"File '{file}' no longer exists."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_ignored_removed_file(file):
    """Create a callback to detect if logcollector is ignoring specified deleted file.
    Args:
        file (str): Absolute path of the deleted file.
    Returns:
        callable: Callback to detect this event.
    """
    msg = f"File not available, ignoring it: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_monitoring_command(log_format, command):
    """Create a callback to detect if logcollector is monitoring a command.
    Args:
        log_format (str): Log format of the command monitoring (full_command or command).
        command (str): Monitored command.
    Returns:
        callable: Callback to detect this event.
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
    msg = fr"ERROR: Could not EvtSubscribe\(\) for \({event_location}\) which returned \(\d+\)"
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


def callback_socket_offline(socket_name, socket_path):
    """Create a callback to detect if a socket that logcollector was connected to is unavailable.

    Args:
        socket_name (str): Socket name.
        socket_path (str): Path to UNIX named socket.

    Returns:
        callable: callback to detect this event.
    """
    msg = f"ERROR: Unable to connect to socket '{socket_name}': {socket_path}"
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
    msg = f"DEBUG: Reading syslog message: '{message}'"
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


def callback_unable_to_open(file_path, n_attempt):
    """Create a callback to detect if `wazuh-logcollector` fails to open the specified file.
    Args:
        file_path (str): Path of the file that `wazuh-logcollector` is trying to open.
        n_attempt (str): Number of attempts remains to ignore the file.
    Returns:
        callable: Callback to detect this event.
    """
    msg = fr"Unable to open file '{file_path}'. Remaining attempts: {n_attempt}"
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
    return monitoring.make_callback(pattern=log_format_message, prefix=prefix)


def callback_trying_to_reconnect(location, reconnect_time):
    """Create a callback to detect if `wazuh-agentd` is trying to reconnect to specified channel.
    Args:
        location (str): Event log channel.
        reconnect_time (str): Reconnect time.
    Returns:
        callable: callback to detect this event.
    """
    log_format_message = f"DEBUG: Trying to reconnect {location} channel in {reconnect_time} seconds."
    return monitoring.make_callback(pattern=log_format_message, prefix=prefix)


def callback_log_stream_exited_error():
    """Create a callback to detect if `log stream` process exited.

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = "ERROR: \(\d+\): macOS 'log stream' process exited"
    return monitoring.make_callback(pattern=log_format_message, prefix=prefix)


def callback_reconnect_eventchannel(location):
    """Create a callback to detect if specified channel has been reconnected successfully.
    Args:
        location (str): Location channel.
    Returns:
        callable: callback to detect this event.
    """
    log_format_message = f"INFO: '{location}' channel has been reconnected succesfully."
    return monitoring.make_callback(pattern=log_format_message, prefix=prefix)


def callback_match_pattern_file(file_pattern, file):
    """Create a callback to detect if logcollector is monitoring a file with wildcard.
    Args:
        file_pattern (str): Location pattern.
        file (str): Name with absolute path of the analyzed file.
    Returns:
        callable: callback to detect this event.
    """
    msg = f"New file that matches the '{file_pattern}' pattern: '{file}'."
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


def callback_invalid_location_value_macos(location):
    """Create a callback to detect if logcollector warns about invalid location value for macos format.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Invalid location value '{location}' when using 'macos' as 'log_format'. Default value will be used."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_missing_location_macos():
    """Create a callback to detect if logcollector warns about missing location value.

    Returns:
        callable: callback to detect this event.
    """
    msg = "Missing 'location' element when using 'macos' as 'log_format'. Default value will be used."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_multiple_macos_block_configuration():
    """Create a callback to detect multiple macos configuration block logcollector error.

    Returns:
        callable: callback to detect this event.
    """
    msg = "Can't add more than one 'macos' block"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_monitoring_macos_logs(old_logs=False):
    """Create a callback to detect if logcollector is monitoring MacOS logs.

    Returns:
        callable: callback to detect this event.
    """
    msg = f"Monitoring macOS old logs with: {MACOS_LOG_COMMAND_PATH} show --style syslog --start" if old_logs else \
        f"Monitoring macOS logs with: {MACOS_LOG_COMMAND_PATH} stream --style syslog"

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


def callback_invalid_format_value(line, option, location):
    """Create a callback to detect content values invalid in a log format file specific.

    Args:
        line(str):  content line of file analized
        option (str): log format value .
        location (str): Wazuh manager configuration option.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    if option == 'json':
        msg = fr"DEBUG: Line '{line}' read from '{location}' is not a JSON object."
    elif option == 'audit':
        msg = "WARNING: Discarding audit message because of invalid syntax."
    elif option == 'nmapg':
        msg = fr"ERROR: Bad formated nmap grepable file."
    elif option == 'djb-multilog':
        msg = fr"DEBUG: Invalid DJB log: '{line}'"

    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_reading_file(log_format, content_file, severity='DEBUG'):
    """Create a callback to detect if the logcollector could read a file with valid content successfully.

    Args:
        log_format(str): Log format type(json, syslog, snort-full, squid, djb-multilog, multi-line:3)
        content_file (str): Content file to analyze
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    if log_format == 'json':
        msg = fr"{severity}: Reading json message: '{content_file}'"
    elif log_format in ['syslog', 'snort-full', 'squid']:
        msg = fr"{severity}: Reading syslog message: '{content_file}'"
    elif log_format == 'multi-line:3':
        msg = fr"{severity}: Reading message: '{content_file}'"

    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_read_file(location):
    """Create a callback to detect when the logcollector reads a file.

    Args:
        location (str): Path Read.

    Returns:
        callable: callback to detect this log.
    """
    msg = fr"lines from {location}"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def get_data_sending_stats(log_path, socket_name):
    """Returns the statistics of a log monitored by logcollector.

    For this purpose, it parses the "wazuh-logcollector.state" file and retrieves the data.
    See:
    https://documentation-dev.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html

    Args:
        log_path (str): Path of the log from which the statistics are to be obtained.
        socket_name (str): Target socket name.

    Returns:
        dict: Dictionary with the statistics.

    Raises:
        FileNotFoundError: If the next statistics could not be obtained according to the interval
                           defined by "logcollector.state_interval".
    """
    wait_statistics_file()

    if not os.path.isfile(LOGCOLLECTOR_STATISTICS_FILE):
        raise FileNotFoundError

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
                for target in targets:
                    if target['name'] == socket_name:
                        stats['global_drops'] = target['drops']
        # Interval statistics
        for i_file in interval_files:
            if i_file['location'] == log_path:
                stats['interval_events'] = i_file['events']
                targets = i_file['targets']
                for target in targets:
                    if target['name'] == socket_name:
                        stats['interval_drops'] = target['drops']
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
        FileNotFoundError: If the next statistics could not be obtained according to the interval
                           defined by "logcollector.state_interval".
    """
    mtime_current = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
    next_interval_date = current_stats['interval_end_date'] + timedelta(seconds=state_interval)
    next_2_intervals_date = current_stats['interval_end_date'] + timedelta(seconds=state_interval * 2)
    for _ in range(state_interval * 2):
        stats = get_data_sending_stats(log_path, socket_name)
        mtime_next = os.path.getmtime(LOGCOLLECTOR_STATISTICS_FILE)
        # The time of the interval must be equal to or greater than the calculated time,
        # but less than the calculated time for two intervals.
        if next_interval_date <= stats['interval_end_date'] < next_2_intervals_date:
            return stats, mtime_next - mtime_current
        else:
            sleep(1)
    raise FileNotFoundError


def create_file_structure(get_files_list):
    """Create the specified file tree structure.

    Args:
        get_files_list(dict):  Files to create.
    """
    for file in get_files_list:
        file_folder_path = file['folder_path']
        files_list = file['filename']
        age = file['age'] if 'age' in file else None
        size = file['size'] if 'size' in file else None
        content = file['content'] if 'content' in file else None
        size_kib = file['size_kib'] if 'size_kib' in file else None

        os.makedirs(file_folder_path, exist_ok=True, mode=0o777)
        for filename in files_list:
            for i in range(0, 5):
                try:
                    with open(os.path.join(file_folder_path, filename), mode='w'):
                        pass
                    break
                except Exception as e:
                    print(f"Error creating file structure {e}")
                    sleep(1)

            if age:
                fileinfo = os.stat(os.path.join(file_folder_path, filename))
                os.utime(os.path.join(file_folder_path, filename), (fileinfo.st_atime - age,
                                                                      fileinfo.st_mtime - age))
            elif size:
                add_log_data(log_path=os.path.join(file_folder_path, filename),
                             log_line_message=content, size_kib=size_kib)


def delete_file_structure(get_files_list):
    """Delete the specified file tree structure.

    Args:
        get_files_list(dict):  Files to delete.
    """

    def remove_readonly(func, path, _):
        """Give write permission to specified path.

        Args:
            func (function): Called function.
            path (str): File path.
        """
        os.chmod(path, stat.S_IWRITE)
        func(path)

    for folder in get_files_list:
        for _ in range(5):
            try:
                shutil.rmtree(folder['folder_path'], onerror=remove_readonly)
            except:
                continue
            break


def callback_invalid_state_interval(interval):
    """Create a callback to detect if logcollector detects an invalid value for logcollector.state_interval option.

    Args:
        interval (str): Value of logcollector.state_interval option.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Invalid definition for logcollector.state_interval: '{interval}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_logcollector_started():
    """Check if logcollector started."""
    return monitoring.make_callback(pattern='Started', prefix=prefix)


def callback_log_bad_predicate():
    """Check for the macOS ULS bad predicate message."""
    return monitoring.make_callback(pattern="Execution error 'log:", prefix=prefix)


def callback_macos_uls_log(expected_message):
    """Callback function to wait for a macOS' ULS log, collected by logcollector."""
    return monitoring.make_callback(pattern=expected_message, prefix=prefix, escape=False)


def callback_logcollector_log_stream_log():
    """Check for logcollector's macOS ULS module start message."""
    return monitoring.make_callback(pattern='Monitoring macOS logs with:(.+?)log stream',
                                    prefix=prefix, escape=False)


def callback_file_status_macos_key():
    """Check for 'macos' key."""
    return monitoring.make_callback(pattern='"macos"', prefix='.*', escape=False)


def callback_log_macos_stream_exit():
    """Check for the macOS ULS log stream exit message."""
    return monitoring.make_callback(pattern="macOS 'log stream' process exited, pid:", prefix=prefix)


def wait_statistics_file(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT):
    """Wait until statistics file is available.

    Raises:
        FileNotFoundError: If the next statistics could not be obtained according to the interval
                           defined by "logcollector.state_interval".
    """
    for _ in range(timeout):
        if os.path.isfile(LOGCOLLECTOR_STATISTICS_FILE):
            break
        else:
            sleep(1)

    if not os.path.isfile(LOGCOLLECTOR_STATISTICS_FILE):
        raise FileNotFoundError


def generate_macos_logger_log(message):
    """Create a unified logging system log using logger tool.

    Args:
        message (str): Logger event message.
    """
    os.system(f"logger {message}")


def generate_macos_custom_log(type, level, subsystem, category, process_name="custom_log"):
    """Create a unified logging system log using log generator script.

    To create a custom event log with desired type, subsystem and category the `log_generator` script is required.
    This, get these parameters and use os_log (https://developer.apple.com/documentation/os/os_log) to create it.
    To correctly run `log_generator` is necessary to compile it. This is done in temporal folder, using `process_name`
    parameter.

    Args:
        type (str):  Log type (trace, activity or log).
        level (str): Log level (info, debug, default, error or fault).
        subsystem (str): Subsystem of the event log.
        category (str): Category of the event log.
        process_name (str): Name of the process that is going to generate the log.
    """
    compiled_log_generator_path = os.path.join(gettempdir(), process_name)
    if not os.path.exists(compiled_log_generator_path):
        os_log_swift_script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           'tools', 'macos_log', 'log_generator.m')
        os.system(f"clang {os_log_swift_script} -o {compiled_log_generator_path}")

    os.system(f'{compiled_log_generator_path} {type} {level} {subsystem} {category}')


def format_macos_message_pattern(process_name, message, type='log', subsystem=None, category=None):
    """Compose expected macos format message that agent is going to send to the manager.

    Args:
        process_name (str): Name of the process that has generated the log.
        message (str): Log message.
        subsystem (str): Log event subsystem.
        category (str): Log event category.
        type (str): Log event type (trace, activity or log)

    Returns:
        string: Expected unified logging system event.
    """
    macos_message = None
    if process_name == 'logger' or type == 'trace':
        macos_message = f"{process_name}\[\d+\]: {message}"
    else:
        if type == 'log':
            macos_message = f"{process_name}\[\d+\]: \[{subsystem}:{category}\] {message}"
        elif type == 'activity':
            macos_message = f"{process_name}\[\d+\]: Created Activity ID.* Description: {message}"

    assert macos_message is not None, 'Wrong type or process name selected for macos message pattern format.'

    return macos_message


def compose_macos_log_command(type='', level='', predicate='', is_sierra=False):
    """
    This function replicates how the command 'log' will be called from the Wazuh agent given the query parameters

    Args:
        type (str): < activity | log | trace > Limit streaming to a given event type.
        level (str): < default | info | debug > Include events at, and below, the given level.
        predicate (str): Filter events using the given predicate.
        is_sierra (boolean): True if running on macOS Sierra, False otherwise.

    Returns:
        string: Full log command composed with the given parameters.
    """

    settings_str = ''

    if (is_sierra):
        settings_str = '/usr/bin/script -q /dev/null '

    settings_str += '/usr/bin/log stream --style syslog '

    if (type):
        for t in type.split(','):
            settings_str += '--type ' + t + ' '

    if (level):
        level = level.replace(' ', '')
        settings_str += '--level ' + level + ' '

    if(predicate):
        settings_str += '--predicate ' + predicate

    return settings_str
