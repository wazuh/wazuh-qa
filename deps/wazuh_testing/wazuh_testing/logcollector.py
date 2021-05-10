import sys
from math import ceil

from wazuh_testing.tools import monitoring

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
        prefix (str): Daemon that generates the error log.

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
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"INFO: Using program name '{program_name}' for DJB multilog file: '{multilog_file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_command_alias_output(alias):
    """Create a callback to detect if logcollector is monitoring a command with an assigned alias.

    Args:
        alias (str): Command alias.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Reading command message: 'ossec: output: '{alias}':"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_eventchannel_bad_format(event_location):
    """Create a callback to detect if logcollector inform about bad formatted eventchannel location.

    Args:
        event_location (str): Eventchannel location.
        prefix (str): Daemon that generates the error log.

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
        prefix (str): Daemon that generates the error log.

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
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"CRITICAL: Socket '{socket_name}' for '{location}' is not defined."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_log_target_not_found(location, socket_name):
    """Create a callback to detect if a log target has not been found.

    Args:
        location (str): Name with the analyzed file.
        socket_name (str): Socket name.
        prefix (str): Daemon that generates the error log.

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
        prefix (str): Daemon that generates the error log.

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
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Glob error. Invalid pattern: '{location}' or no files found."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_read_lines(command, escape=False):
    """Create a callback to detect "DEBUG: Read <number> lines from command <command>" debug line.

    Args:
        command (str): Command to be monitored.
        prefix (str): Daemon that generates the log.
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
        prefix (str): Daemon that generates the log.
        escape (bool): Flag to escape special characters in the pattern.

    Returns:
        callable: callback to detect this event.
    """
    log_format_message = 'full command' if log_format == 'full_command' else 'command'
    msg = fr"DEBUG: Running {log_format_message} '{command}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=escape)


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
            if print_line_num is True:
                for x in range(line_start, line_start + lines + 1):
                    f.write(f"{log_line_message}{x}\n")
            else:
                for x in range(line_start, line_start + lines + 1):
                    f.write(f"{log_line_message}\n")
        return line_start + lines - 1
    return 0
