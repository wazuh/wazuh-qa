import re

from wazuh_testing import T_10, T_60
from wazuh_testing.modules.analysisd import ANALYSISD_PREFIX, MAILD_PREFIX, TESTRULE_PREFIX
from wazuh_testing import LOG_FILE_PATH, ANALYSISD_STATE
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback


# Callback events
CB_SID_NOT_FOUND = r".*Signature ID '(\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\d*)'"
CB_EMPTY_IF_SID_RULE_IGNORED = fr"{TESTRULE_PREFIX}Empty 'if_sid' value. Rule '(\d*)' will be ignored.*"
CB_INVALID_IF_SID_RULE_IGNORED = fr"{TESTRULE_PREFIX}Invalid 'if_sid' value: '(.*)'. Rule '(\d*)' will be ignored.*"
CB_INVALID_EMPTY_IF_SID_RULE_IGNORED = fr"{TESTRULE_PREFIX}Invalid 'if_sid' value: ''. Rule '(\d*)' will be ignored.*"

# Error Messages
ERR_MSG_SID_NOT_FOUND = "Did not receive the expected 'Signature ID  not found...' event"
ERR_MSG_EMPTY_IF_SID = "Did not receive the expected 'Empty 'if_sid' value. Rule '(\\d*)' will be ignored' event"
ERR_MSG_INVALID_IF_SID = "Did not receive the expected 'Invalid 'if_sid' value. Rule '(\\d*)' will be ignored' event"


def make_analysisd_callback(pattern, prefix=ANALYSISD_PREFIX):
    """Create a callback function from a text pattern.

    It already contains the analsisd prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as a prefix before the pattern.

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_bionic_update_started = make_vuln_callback("Starting Ubuntu Bionic database update")
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_analysisd_event(file_monitor=None, callback='', error_message=None, update_position=True,
                          timeout=T_60, prefix=ANALYSISD_PREFIX, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if a analysisd event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        prefix (str): log pattern regex
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_analysisd_callback(callback, prefix), error_message=error_message)


def check_eps_disabled():
    """Check if the eps module is disabled"""
    check_analysisd_event(callback=r".*INFO: EPS limit disabled.*", timeout=T_10)


def check_eps_missing_maximum():
    """Check if the eps block has the maximum tag"""
    check_analysisd_event(callback=r".*WARNING: EPS limit disabled. "
                                   "The maximum value is missing in the configuration block.*",
                          timeout=T_10)


def check_eps_enabled(maximum, timeframe):
    """Check if the eps module is enable"""
    check_analysisd_event(callback=fr".*INFO: EPS limit enabled, EPS: '{maximum}', timeframe: '{timeframe}'",
                          timeout=T_10)


def check_configuration_error():
    """Check the configuration error event in ossec.log"""
    check_analysisd_event(timeout=T_10, callback=r".* \(\d+\): Configuration error at.*",
                          error_message="Could not find the event 'Configuration error at 'etc/ossec.conf' "
                                        'in ossec.log', prefix=MAILD_PREFIX)


def get_analysisd_state():
    """Get the states values of wazuh-analysisd.state file

    Returns:
        dict: Dictionary with all analysisd state
    """
    data = ""
    with open(ANALYSISD_STATE, 'r') as file:
        for line in file.readlines():
            if not line.startswith("#") and not line.startswith('\n'):
                data = data + line.replace('\'', '')
    data = data[:-1]
    analysisd_state = dict((a.strip(), b.strip()) for a, b in (element.split('=') for element in data.split('\n')))

    return analysisd_state


def check_queues_are_full_and_no_eps_credits_log(log_level='WARNING', timeout=T_10):
    """Check if the start dropping events log is shown.

    Args:
        log_level (str): Log level.
        timeout (int): Timeout for checking the event in log.
    """
    check_analysisd_event(callback=fr'.*{log_level}: Queues are full and no EPS credits, dropping events.*',
                          timeout=timeout)


def check_stop_dropping_events_and_credits_available_log(log_level='WARNING', timeout=T_10):
    """Check if the stop dropping events log is shown

    Args:
        log_level (str): Log level.
        timeout (int): Timeout for checking the event in log.
    """
    check_analysisd_event(callback=fr'.*{log_level}: Queues back to normal and EPS credits, no dropping events.*',
                          timeout=timeout)


def check_if_sid_not_found(file_monitor):
    """Check if an invalid if_sid rule value is ignored when detected

    Args:
        file_monitor (FileMonitor): Log monitor.
    """
    file_monitor.start(timeout=T_10, callback=generate_monitoring_callback(CB_SID_NOT_FOUND),
                       error_message=ERR_MSG_SID_NOT_FOUND)


def check_invalid_if_sid(file_monitor, is_empty):
    """Check if an invalid if_sid rule value is ignored when detected

    Args:
        file_monitor (FileMonitor): Log monitor.
        is_empty (Boolean): True if is_sid tag has nothing inside/ is empty.
    """
    callback = CB_INVALID_EMPTY_IF_SID_RULE_IGNORED if is_empty else CB_INVALID_IF_SID_RULE_IGNORED

    file_monitor.start(timeout=T_10, callback=generate_monitoring_callback(callback),
                       error_message=ERR_MSG_INVALID_IF_SID)


def check_empty_if_sid(file_monitor):
    """Check if an invalid if_sid rule value is ignored when detected

    Args:
        file_monitor (FileMonitor): Log monitor.
    """
    file_monitor.start(timeout=T_10, callback=generate_monitoring_callback(CB_EMPTY_IF_SID_RULE_IGNORED),
                       error_message=ERR_MSG_EMPTY_IF_SID)
