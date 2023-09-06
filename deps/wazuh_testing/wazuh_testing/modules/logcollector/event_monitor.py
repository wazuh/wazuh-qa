import re
import sys
import pytest
from wazuh_testing import T_30, T_10, LOG_FILE_PATH
from wazuh_testing.modules.logcollector import LOG_COLLECTOR_PREFIX, ERR_MSG_UNEXPECTED_IGNORE_EVENT
from wazuh_testing.tools.monitoring import FileMonitor


def make_logcollector_callback(pattern, prefix=LOG_COLLECTOR_PREFIX, escape=False):
    """Create a callback function from a text pattern.

    It already contains the logcollector prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as a prefix before the pattern.
        escape (bool): Flag to escape special characters in the pattern

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_message = make_vuln_callback("DEBUG: Reading syslog message")
    """
    if escape:
        pattern = re.escape(pattern)
    else:
        pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_logcollector_event(file_monitor=None, callback='', error_message=None, update_position=True,
                             timeout=T_30, prefix=LOG_COLLECTOR_PREFIX, accum_results=1, file_to_monitor=LOG_FILE_PATH,
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

    result = file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                                callback=make_logcollector_callback(callback, prefix, escape),
                                error_message=error_message).result()
    return result


def check_analyzing_file(file, prefix, error_message=None, file_monitor=None):
    """Create a callback to detect if logcollector is monitoring a file.

    Args:
        file (str): Name with absolute path of the analyzed file.
        error_message (str): Error message.
        prefix (str): Daemon that generates the error log.
        file_monitor (FileMonitor): Log monitor.
    """
    if error_message is None:
        error_message = f"Did not receive the expected 'Analyzing file: {file}' event"

    check_logcollector_event(file_monitor=file_monitor, timeout=T_30,
                             callback=fr".*Analyzing file: '{file}'.*",
                             error_message=error_message, prefix=prefix)


def check_syslog_message(message, prefix, error_message=None, file_monitor=None, timeout=T_30, escape=False):
    """Create a callback to detect "DEBUG: Read <number> lines from command <command>" debug line.

    Args:
        message (str): Command to be monitored.
        error_message (str): Error message.
        prefix (str): Daemon that generates the error log.
        file_monitor (FileMonitor): Log monitor.
        timeout (int): Timeout to check the log.
        escape (bool): Flag to escape special characters in the pattern.
    """
    if error_message is None:
        error_message = f"Did not receive the expected 'Reading syslog message: {message}' event"

    callback_msg = fr".*DEBUG: Reading syslog message: '{message}'.*"

    check_logcollector_event(file_monitor=file_monitor, timeout=timeout, callback=callback_msg,
                             error_message=error_message, prefix=prefix, escape=escape)


def check_ignore_restrict_message(message, regex, tag, prefix, error_message=None, file_monitor=None, timeout=T_10,
                                  escape=False):
    """Create a callback to detect "DEBUG: Ignoring the log ... due to config" debug line.

    Args:
        message (str): Command to be monitored.
        regex (str): regex pattern configured to ignore or restrict to.
        tag (str): string with the configured tag. Values: 'ignore' or 'restrict'
        error_message (str): Error message.
        prefix (str): Daemon that generates the error log.
        file_monitor (FileMonitor): Log monitor.
        timeout (int): Timeout to check the log.
        escape (bool): Flag to escape special characters in the pattern.

    Returns: True if the expected message has been found, False otherwise.
    """
    if error_message is None:
        error_message = f"Did not receive the expected 'Ignoring the log line: {message} due to {tag} config' event"

    callback_msg = fr"Ignoring the log line '{message}' due to {tag} config: '{regex}'"

    return check_logcollector_event(file_monitor=file_monitor, timeout=timeout, callback=callback_msg,
                                    error_message=error_message, prefix=prefix, escape=escape)


def check_ignore_restrict_message_not_found(message, regex, tag, prefix):
    """Check that an unexpected "Ignoring the log line..." event does not appear and a log is not ignored when it
       does not match the regex.

    Args:
        message (str): Message to be monitored.
        regex (str): regex pattern configured to ignore or restrict to.
        tag (str): string with the configured tag. Values: 'ignore' or 'restrict'
        prefix (str): Daemon that generates the error log.
    """
    log_found = False
    with pytest.raises(TimeoutError):
        log_found = check_ignore_restrict_message(message=message, regex=regex, tag=tag, prefix=prefix)
    assert log_found is False, ERR_MSG_UNEXPECTED_IGNORE_EVENT


def check_wildcard_pattern_expanded(file_path, location_regex, prefix, error_message=None, file_monitor=None,
                                    timeout=T_10, escape=False):
    """Create a callback to detect "New file that matches the '{file_path}' pattern: '(.*)'" line.
    Args:
        file_path (str): file path that is being monitored
        location_regex (str): path configured in location tag
        prefix (str): Daemon that generates the error log.
        error_message (str): Error message.
        file_monitor (FileMonitor): Log monitor.
        timeout (int): Timeout to check the log.
        escape (bool): Flag to escape special characters in the pattern.
    Returns: True if the expected message has been found, False otherwise.
    """
    callback_msg = f".*New file that matches the '{location_regex}' pattern: '{file_path}'"

    return check_logcollector_event(file_monitor=file_monitor, timeout=timeout, callback=callback_msg,
                                    error_message=error_message, prefix=prefix, escape=escape)


def check_win_wildcard_pattern_no_match(regex, prefix, error_message=None, file_monitor=None, timeout=T_10,
                                        escape=False):
    """Create a callback to detect "DEBUG: No file/folder that matches ..." line.
    Args:
        regex (str): regex pattern configured in location tag for monitoring
        prefix (str): Daemon that generates the error log.
        error_message (str): Error message.
        file_monitor (FileMonitor): Log monitor.
        timeout (int): Timeout to check the log.
        escape (bool): Flag to escape special characters in the pattern.
    Returns: True if the expected message has been found, False otherwise.
    """
    callback_msg = f".*expand_win32_wildcards.*DEBUG: No .* that matches {regex}"

    return check_logcollector_event(file_monitor=file_monitor, timeout=timeout, callback=callback_msg,
                                    error_message=error_message, prefix=prefix, escape=escape)
