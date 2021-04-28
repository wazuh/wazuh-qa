from wazuh_testing.tools import monitoring

GENERIC_CALLBACK_ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
GENERIC_CALLBACK_ERROR_INVALID_LOCATION = 'The expected invalid location error log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_FILE = 'The expected analyzing file log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL = "The expected analyzing eventchannel log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET = "The expected target socket log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET_NOT_FOUND = "The expected target socket not found error has not been produced"


def callback_analyzing_file(file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    """Create a callback to detect if logcollector is monitoring a file.

    Args:
        file (str): Name with absolute path of the analyzed file.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_monitoring_command(log_format, command, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
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


def callback_monitoring_djb_multilog(program_name, multilog_file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
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


def callback_command_alias_output(alias, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    """Create a callback to detect if logcollector is monitoring a command with an assigned alias.

    Args:
        alias (str): Command alias.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Reading command message: 'ossec: output: '{alias}':"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_eventchannel_bad_format(event_location, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    """Create a callback to detect if logcollector inform about bad formatted eventchannel location.

    Args:
        event_location (str): Eventchannel location.
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: Could not EvtSubscribe() for ({event_location}) which returned \(\d+\)"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_socket_target(location, socket_name, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
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


def callback_socket_not_defined(location, socket_name, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
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


def callback_log_target_not_found(location, socket_name, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
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


def callback_invalid_reconnection_time(severity='WARNING', default_value='5',
                                       prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
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
    return monitoring.make_callback(pattern=msg, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_invalid_location_pattern(location, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    """Create a callback to detect if invalid location pattern has been used.

    Args:
        location (str): Location pattern
        prefix (str): Daemon that generates the error log.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"Glob error. Invalid pattern: '{location}' or no files found."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_ignoring_file(location_file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"DEBUG: Ignoring file '{location_file}' due to modification time"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_file_matches_pattern(location_pattern, location_file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"New file that matches the '{location_pattern}' pattern: '{location_file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_reading_syslog_message(message, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"DEBUG: Reading syslog message: '{message}'"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_read_line_from_file(n_lines, filename, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"DEBUG: Read {n_lines} lines from {filename}"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)
