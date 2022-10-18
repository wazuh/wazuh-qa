import re

from wazuh_testing.modules import engine
from wazuh_testing.tools.monitoring import FileMonitor


def make_engine_callback(pattern, prefix=engine.ENGINE_PREFIX):
    """Create a callback function from a text pattern.

    It already contains the vulnerability-detector prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as prefix before the pattern.

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_bionic_update_started = make_vuln_callback("Starting Ubuntu Bionic database update")
    """
    pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None

def check_engine_json_event(file_monitor=None, event='', error_message=None, update_position=True,
                              timeout=engine.T_1, accum_results=1, prefix=engine.ENGINE_PREFIX,
                              file_to_monitor=engine.ENGINE_OUTPUT_PATH):

    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {event}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_engine_callback(event, prefix), error_message=error_message)
