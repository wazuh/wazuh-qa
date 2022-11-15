from wazuh_testing import T_5, T_10
from wazuh_testing.modules import syscollector as sysc, make_callback
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor


def check_syscollector_event(file_monitor=None, callback='', error_message=None, update_position=True, timeout=T_10,
                             prefix=sysc.SYSCOLLECTOR_PREFIX, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if a syscollector event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        prefix (str): log pattern regex
        accum_results (int): Accumulation of matches.

    Returns:
        result (list of any): It can return either a list of any type or simply any type.
                              If `accum_results > 1`, it will be a list.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    result = file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                                callback=make_callback(callback, prefix), error_message=error_message).result()

    return result


def check_has_started(timeout=T_5):
    """Check if the syscollector scan has started"""
    check_syscollector_event(callback='DEBUG: Starting Syscollector.', timeout=timeout)


def check_startup_finished(timeout=T_5, prefix=sysc.SYSCOLLECTOR_PREFIX):
    """Check if the syscollector startup was completed.

    Args:
        timeout (str): timeout to check the event in Wazuh log
        prefix (str): log pattern regex

    Returns:
        result (list of any): It can return either a list of any type or simply any type.
                              If `accum_results > 1`, it will be a list.
    """
    result = check_syscollector_event(callback='INFO: Module started.', timeout=timeout, prefix=prefix)

    return result


def check_scan_started(timeout=T_5, prefix=sysc.SYSCOLLECTOR_PREFIX):
    """Check if the syscollector scan has started

    Args:
        timeout (str): timeout to check the event in Wazuh log
        prefix (str): log pattern regex

    Returns:
        result (list of any): It can return either a list of any type or simply any type.
                              If `accum_results > 1`, it will be a list.
    """
    result = check_syscollector_event(callback='INFO: Starting evaluation.', timeout=timeout, prefix=prefix)

    return result


def check_scan_finished(timeout=T_5):
    """Check if the syscollector scan has finished"""
    check_syscollector_event(callback='INFO: Evaluation finished.', timeout=timeout)


def check_sync_started(timeout=T_5):
    """Check if the syscollector synchronization has started"""
    check_syscollector_event(callback='DEBUG: Starting syscollector sync', timeout=timeout)


def check_sync_finished(timeout=T_5):
    """Check if the syscollector synchronization has finished"""
    check_syscollector_event(callback='DEBUG: Ending syscollector sync', timeout=timeout)


def check_disabled(timeout=T_5):
    """Check if the syscollector module is disabled"""
    check_syscollector_event(callback='INFO: Module disabled. Exiting...', timeout=timeout)


def check_config(disabled='no', interval=3600, scan_on_start='yes', hardware='yes', os='yes', ports='yes',
                 network='yes', packages='yes', ports_all='no', processes='yes', hotfixes='yes', max_eps=10,
                 timeout=T_5):
    """Check if the syscollector configuration was applied correctly.

    Args:
        disabled (str): Disable the Syscollector wodle.
        interval (int): Time between system scans.
        scan_on_start (str): Run a system scan immediately when service is started.
        hardware (str): Enables the hardware scan.
        os (str): Enables the OS scan.
        ports (str): Enables the ports scan.
        network (str): Enables the network scan.
        packages (str): Enables the packages scan.
        ports_all (str): Make Wazuh only scans listening ports.
        processes (str): Enables the processes scan.
        hotfixes (str): Enables the hotfixes scan.
        max_eps (int): Sets the maximum event reporting throughput.
    """
    msg = 'DEBUG:.+"disabled":"{0}","scan-on-start":"{1}","interval":{2},'.format(disabled, scan_on_start, interval)
    msg += '"network":"{0}","os":"{1}","hardware":"{2}","packages":"{3}","ports":"{4}",'.format(network, os, hardware,
                                                                                                packages, ports)
    msg += '"ports_all":"{0}","processes":"{1}","sync_max_eps":{2}.+'.format(ports_all, processes, max_eps)

    check_syscollector_event(callback=msg, timeout=timeout)


def check_hardware_scan_started(timeout=T_5):
    """Check if the syscollector hardware scan has started"""
    check_syscollector_event(callback='DEBUG: Starting hardware scan', timeout=timeout)


def check_hardware_scan_finished(timeout=T_5):
    """Check if the syscollector OS scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending hardware scan', timeout=timeout)


def check_os_scan_started(timeout=T_5):
    """Check if the syscollector OS scan has started"""
    check_syscollector_event(callback='DEBUG: Starting os scan', timeout=timeout)


def check_os_scan_finished(timeout=T_5):
    """Check if the syscollector OS scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending os scan', timeout=timeout)


def check_network_scan_started(timeout=T_5):
    """Check if the syscollector network scan has started"""
    check_syscollector_event(callback='DEBUG: Starting network scan', timeout=timeout)


def check_network_scan_finished(timeout=T_5):
    """Check if the syscollector network scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending network scan', timeout=timeout)


def check_packages_scan_started(timeout=T_5):
    """Check if the syscollector packages scan has started"""
    check_syscollector_event(callback='DEBUG: Starting packages scan', timeout=timeout)


def check_packages_scan_finished(timeout=T_5):
    """Check if the syscollector packages scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending packages scan', timeout=timeout)


def check_ports_scan_started(timeout=T_5):
    """Check if the syscollector ports scan has started"""
    check_syscollector_event(callback='DEBUG: Starting ports scan', timeout=timeout)


def check_ports_scan_finished(timeout=T_5):
    """Check if the syscollector ports scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending ports scan', timeout=timeout)


def check_processes_scan_started(timeout=T_5):
    """Check if the syscollector processes scan has started"""
    check_syscollector_event(callback='DEBUG: Starting processes scan', timeout=timeout)


def check_processes_scan_finished(timeout=T_5):
    """Check if the syscollector processes scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending processes scan', timeout=timeout)


def check_hotfixes_scan_started(timeout=T_5):
    """Check if the syscollector hotfixes scan has started"""
    check_syscollector_event(callback='DEBUG: Starting hotfixes scan', timeout=timeout)


def check_hotfixes_scan_finished(timeout=T_5):
    """Check if the syscollector hotfixes scan has finished"""
    check_syscollector_event(callback='DEBUG: Ending hotfixes scan', timeout=timeout)


def check_tag_error(field='', timeout=T_5, prefix='.+wmodules_syscollector.+'):
    """Check if syscollector shows an error when using an invalid value in a tag."""
    callbacks = {
        'max_eps': "WARNING:.+ Invalid value for element 'max_eps': .+",
        'interval': "ERROR: Invalid interval at module 'syscollector'",
        'all': f"ERROR: Invalid content for tag '{field}' at module 'syscollector'."
    }
    callback = callbacks['all'] if field not in callbacks.keys() else callbacks[field]

    check_syscollector_event(callback=callback, timeout=timeout, prefix=prefix)


def check_attr_error(attr='', timeout=T_5, prefix='.+wmodules_syscollector.+'):
    """Check if syscollector shows an error when using an invalid value in an attribute."""
    check_syscollector_event(callback=f"ERROR: Invalid content for attribute '{attr}' at module 'syscollector'.",
                             timeout=timeout, prefix=prefix)
