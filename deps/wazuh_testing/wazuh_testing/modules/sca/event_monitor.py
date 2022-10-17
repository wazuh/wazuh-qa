import re

from wazuh_testing.tools import LOG_FILE_PATH, ALERT_FILE_PATH
from wazuh_testing.modules import sca
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback


def check_sca_event(file_monitor=None, callback='', error_message=None, update_position=True,
                              timeout=sca.T_60, accum_results=1,file_to_monitor=LOG_FILE_PATH):
    """Check if a sca event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=generate_monitoring_callback(callback), error_message=error_message)


def check_sca_enabled():
    """Check if the sca module is enabled"""
    check_sca_event(callback=sca.CB_SCA_ENABLED, timeout=sca.T_10)


def check_sca_disabled():
    """Check if the sca module is disabled"""
    check_sca_event(callback=sca.CB_SCA_DISABLED, timeout=sca.T_10)