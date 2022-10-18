import re

from wazuh_testing import T_30, T_60
from wazuh_testing.modules.logcollector import LOG_COLLECTOR_PREFIX, MACOS_LOG_COMMAND_PATH
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import LOG_FILE_PATH


def make_logcollector_callback(pattern, prefix=LOG_COLLECTOR_PREFIX, escape=False):
    """Create a callback function from a text pattern.

    It already contains the analsisd prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as a prefix before the pattern.
        escape (bool): Flag to escape special characters in the pattern

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_bionic_update_started = make_vuln_callback("Starting Ubuntu Bionic database update")
    """
    if escape:
        pattern = re.escape(pattern)
    else:
        pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_logcollector_event(file_monitor=None, callback='', error_message=None, update_position=True,
                             timeout=T_60, prefix=LOG_COLLECTOR_PREFIX, accum_results=1, file_to_monitor=LOG_FILE_PATH,
                             escape=False):
    """Check if a logcollector event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        prefix (str): log pattern regex
        accum_results (int): Accumulation of matches.
        escape (bool): Flag to escape special characters in the pattern
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_logcollector_callback(callback, prefix, escape), error_message=error_message)


def check_eventchannel_analyzing(event_location, error_message, prefix):
    """Check if logcollector is monitoring a event log.

    Args:
        event_location (str): Event log location.
        error_message (str): Error message.
        prefix (str): Prefix.
    """
    check_logcollector_event(timeout=T_30, callback=fr".*INFO: \(\d+\): Analyzing event log: '{event_location}'.",
                             error_message=error_message, prefix=prefix)


def check_monitoring_macos_logs(error_message, old_logs=False):
    """Check if logcollector is monitoring MacOS logs.

    Args:
        error_message (str): Error message.
        old_logs (bool): Flag that indicates if it is reading old logs.
    """
    log_msg = re.escape(MACOS_LOG_COMMAND_PATH)
    callback_msg = f"Monitoring macOS old logs with: {log_msg} show --style syslog --start" \
                   if old_logs else f"Monitoring macOS logs with: {log_msg} stream --style syslog"

    check_logcollector_event(timeout=T_30, callback=callback_msg, error_message=error_message)


def check_analyzing_file(file, error_message, prefix):
    """Create a callback to detect if logcollector is monitoring a file.

    Args:
        file (str): Name with absolute path of the analyzed file.
        error_message (str): Error message.
        prefix (str): Daemon that generates the error log.
    """
    check_logcollector_event(timeout=T_30, callback=fr".*Analyzing file: '{re.escape(file)}'.*",
                             error_message=error_message, prefix=prefix)


def check_invalid_attribute(option, attribute, value, prefix, severity='WARNING'):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        attribute (str): Wazuh manager configuration attribute.
        value (str): Value of the configuration option.
        prefix (str): Daemon that generates the error log.
        severity (str): Severity of the error (WARNING, ERROR or CRITICAL)

    Returns:
        callable: callback to detect this event.
    """
    callback_msg = fr".*{severity}: \(\d+\): Invalid value '{value}' for attribute '{attribute}' in '{option}' option.*"
    check_logcollector_event(timeout=T_30, callback=callback_msg, prefix=prefix)


def check_invalid_value(option, value, prefix, severity='ERROR'):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        value (str): Value of the configuration option.
        prefix (str): Daemon that generates the error log.
        severity (str): Severity of the error (WARNING, ERROR or CRITICAL)

    Returns:
        callable: callback to detect this event.
    """
    callback_msg = fr".*{severity}: \(\d+\): Invalid value for element '{option}': {value}."
    check_logcollector_event(timeout=T_30, callback=callback_msg, prefix=prefix)


def check_configuration_error():
    """Check the configuration error event in ossec.log"""
    check_logcollector_event(timeout=T_30, callback=r".* \(\d+\): Configuration error at.*",
                             error_message="Could not find the event 'Configuration error at 'etc/ossec.conf' "
                                           'in ossec.log', prefix='.*wazuh-logcollector.*')


def check_running_command(log_format, command, error_message, prefix, file_monitor=None, timeout=T_30, escape=False):
    """Create a callback to detect "DEBUG: Running <log_format> '<command>'" debug line.

    Args:
        log_format (str): Log format of the command monitoring (full_command or command).
        command (str): Command to be monitored.
        error_message (str): Error message.
        prefix (str): Daemon that generates the error log.
        file_monitor (FileMonitor): Log monitor.
        timeout (int): Timeout to check the log.
        escape (bool): Flag to escape special characters in the pattern.
    """
    log_format_message = 'full command' if log_format == 'full_command' else 'command'
    callback_msg = fr"DEBUG: Running {log_format_message} '{command}'"
    check_logcollector_event(file_monitor=file_monitor, timeout=timeout, callback=callback_msg,
                             error_message=error_message, prefix=prefix, escape=escape)


def check_read_lines(command, error_message, prefix, file_monitor=None, timeout=T_30, escape=False):
    """Create a callback to detect "DEBUG: Read <number> lines from command <command>" debug line.
    Args:
        command (str): Command to be monitored.
        error_message (str): Error message.
        prefix (str): Daemon that generates the error log.
        file_monitor (FileMonitor): Log monitor.
        timeout (int): Timeout to check the log.
        escape (bool): Flag to escape special characters in the pattern.
    """
    callback_msg = fr"lines from command '{command}'"
    check_logcollector_event(file_monitor=file_monitor, timeout=timeout, callback=callback_msg,
                             error_message=error_message, prefix=prefix, escape=escape)
