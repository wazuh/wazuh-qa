from wazuh_testing.modules import api

from wazuh_testing.tools.monitoring import FileMonitor


def check_api_event(file_monitor=None, callback='', error_message=None, update_position=True, timeout=api.T_20,
                    prefix=api.API_PREFIX, accum_results=1, file_to_monitor=API_LOG_FILE_PATH):
    """Check if an API event occurs

    Args:
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                      callback=make_vuln_callback(callback, prefix), error_message=error_message)
