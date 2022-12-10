import re

from wazuh_testing.tools.monitoring import FileMonitor


def make_callback(pattern, prefix=''):
    """Create a callback function from a text pattern.
    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as prefix before the pattern.
    Returns:
        lambda: function that returns if there's a match in the file
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line)


def check_event(file_monitor=None, callback='', error_message=None, update_position=True, timeout=20,
                accum_results=1, file_to_monitor=None, prefix=''):
    """Check if an API event occurs
    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in the file
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in the file
        timeout (str): timeout to check the event in the file
        prefix (str): log pattern regex
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    result = file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                                callback=make_callback(callback, prefix), error_message=error_message)

    return result
