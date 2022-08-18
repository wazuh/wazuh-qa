import re
from datetime import datetime

from wazuh_testing.modules import eps as eps
from wazuh_testing.tools import LOG_FILE_PATH, ANALYSISD_STATE, ALERT_LOGS_PATH
from wazuh_testing.tools.monitoring import FileMonitor


def make_analysisd_callback(pattern, prefix=eps.ANALYSISD_PREFIX):
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
                          timeout=eps.T_60, prefix=eps.ANALYSISD_PREFIX, accum_results=1,
                          file_to_monitor=LOG_FILE_PATH):
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
    check_analysisd_event(callback=fr'.*INFO: EPS limit disabled.*', timeout=eps.T_10)


def check_eps_enabled(maximum, timeframe):
    """Check if the eps module is enable"""
    check_analysisd_event(callback=fr".*INFO: EPS limit enabled, EPS: '{maximum}', timeframe: '{timeframe}'",
                          timeout=eps.T_10)


def check_configuration_error():
    """Check the configuration error event in ossec.log"""
    check_analysisd_event(timeout=eps.T_10, callback=r".* \(\d+\): Configuration error at.*",
                          error_message="Could not find the event 'Configuration error at 'etc/ossec.conf' "
                                        'in ossec.log', prefix=eps.MAILD_PREFIX)


def find_in_file(string_to_search, filename):
    """Find a specific string in a file

    Args:
        string_to_search (str): Word to find in the file
    Returns:
        str: Line that match in file
    """
    with open(filename, 'r') as file:
        for _, line in enumerate(file):
            if string_to_search in line:
                return line


def get_analysisd_state(value):
    """Get the specified wazuh-analysisd.state value

    Args:
        value (str): wazuh-analisysd value
    """
    line = find_in_file(value, ANALYSISD_STATE)
    return float(line.split("\'")[1::2][0])


def get_alert_timestamp(start_log, end_log):
    """Get the timestamp of the alert if exist in the alerts.log file between two string

    Args:
        start_log (str): Start message to find
        end_log (str): End message to find
    """
    with open(ALERT_LOGS_PATH, 'r') as file:
        str_file = file.read()
        index1 = str_file.find(end_log)
        index2 = str_file[0: index1].rfind(start_log)
        str_alert = str_file[index2: index1]
        timestamp = str_alert[str_alert.find(start_log) + len(start_log):str_alert.find(': ')]

        return datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')


def get_msg_with_number(message):
    """Check if the alerts.log file contains the message

    Args:
        message (str): Message to find
    """
    check_analysisd_event(timeout=eps.T_20, callback=message,
                          error_message=fr"Could not find the event: {message}",  prefix="",
                          file_to_monitor=ALERT_LOGS_PATH)
