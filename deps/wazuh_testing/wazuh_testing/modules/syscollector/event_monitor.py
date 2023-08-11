"""
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import sys

from wazuh_testing import T_5
from wazuh_testing.event_monitor import check_event


# Define the log messages prefix
SYSCOLLECTOR_PREFIX = '.+wazuh-modulesd:syscollector.+'
WMODULES_SYSCOLLECTOR_PREFIX = '.+wmodules-syscollector.+'

# Callback messages
CB_MODULE_STARTING = 'DEBUG: Starting Syscollector.'
CB_MODULE_STARTED = 'INFO: Module started.'
CB_SCAN_STARTED = 'INFO: Starting evaluation.'
CB_SCAN_FINISHED = 'INFO: Evaluation finished.'
CB_SYNC_STARTED = 'DEBUG: Starting syscollector sync'
CB_SYNC_FINISHED = 'DEBUG: Ending syscollector sync'
CB_SYSCOLLECTOR_DISABLED = 'INFO: Module disabled. Exiting...'
CB_HARDWARE_SCAN_STARTED = 'DEBUG: Starting hardware scan'
CB_HARDWARE_SCAN_FINISHED = 'DEBUG: Ending hardware scan'
CB_OS_SCAN_STARTED = 'DEBUG: Starting os scan'
CB_OS_SCAN_FINISHED = 'DEBUG: Ending os scan'
CB_NETWORK_SCAN_STARTED = 'DEBUG: Starting network scan'
CB_NETWORK_SCAN_FINISHED = 'DEBUG: Ending network scan'
CB_PACKAGES_SCAN_STARTED = 'DEBUG: Starting packages scan'
CB_PACKAGES_SCAN_FINISHED = 'DEBUG: Ending packages scan'
CB_PORTS_SCAN_STARTED = 'DEBUG: Starting ports scan'
CB_PORTS_SCAN_FINISHED = 'DEBUG: Ending ports scan'
CB_PROCESSES_SCAN_STARTED = 'DEBUG: Starting processes scan'
CB_PROCESSES_SCAN_FINISHED = 'DEBUG: Ending processes scan'
CB_HOTFIXES_SCAN_STARTED = 'DEBUG: Starting hotfixes scan'
CB_HOTFIXES_SCAN_FINISHED = 'DEBUG: Ending hotfixes scan'


def check_module_is_starting(file_monitor=None, timeout=T_5):
    """Check if the syscollector module is starting.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_MODULE_STARTING, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_module_startup_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector startup was completed.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_MODULE_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_sync_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector synchronization has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_SYNC_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_syscollector_is_disabled(file_monitor=None, timeout=T_5):
    """Check if the syscollector module is disabled.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_SYSCOLLECTOR_DISABLED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_config(disabled='no', interval=3600, scan_on_start='yes', hardware='yes', os='yes', ports='yes',
                 network='yes', packages='yes', ports_all='no', processes='yes', hotfixes='yes', max_eps=10,
                 file_monitor=None, timeout=T_5):
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
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    msg = 'DEBUG:.+"disabled":"{0}","scan-on-start":"{1}","interval":{2},'.format(disabled, scan_on_start, interval)
    msg += '"network":"{0}","os":"{1}","hardware":"{2}","packages":"{3}","ports":"{4}",'.format(network, os, hardware,
                                                                                                packages, ports)
    msg += '"ports_all":"{0}","processes":"{1}",'.format(ports_all, processes)
    if sys.platform == 'win32':
        msg += '"hotfixes":"{0}",'.format(hotfixes)
    msg += '"sync_max_eps":{0}.+'.format(max_eps)

    check_event(callback=msg, timeout=timeout, file_monitor=file_monitor)


def check_hardware_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector hardware scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_HARDWARE_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_hardware_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector OS scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_HARDWARE_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_os_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector OS scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_OS_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_os_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector OS scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_OS_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_network_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector network scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_NETWORK_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_network_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector network scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_NETWORK_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_packages_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector packages scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_PACKAGES_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_packages_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector packages scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_PACKAGES_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_ports_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector ports scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_PORTS_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_ports_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector ports scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_PORTS_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)


def check_processes_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector processes scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_PROCESSES_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_processes_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector processes scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_PROCESSES_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_hotfixes_scan_started(file_monitor=None, timeout=T_5):
    """Check if the syscollector hotfixes scan has started.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_HOTFIXES_SCAN_STARTED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_hotfixes_scan_finished(file_monitor=None, timeout=T_5):
    """Check if the syscollector hotfixes scan has finished.

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    check_event(callback=CB_HOTFIXES_SCAN_FINISHED, timeout=timeout, prefix=SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_tag_error(field='', file_monitor=None, timeout=T_5):
    """Check if syscollector shows an error when using an invalid value in a tag.

    Args:
        field (str): field that contains the error.
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    callbacks_options = {
        'max_eps': "WARNING:.+ Invalid value for element 'max_eps': .+",
        'interval': "ERROR: Invalid interval at module 'syscollector'",
        'all': f"ERROR: Invalid content for tag '{field}' at module 'syscollector'."
    }
    selected_callback = callbacks_options['all'] if field not in callbacks_options.keys() else callbacks_options[field]

    check_event(callback=selected_callback, timeout=timeout, prefix=WMODULES_SYSCOLLECTOR_PREFIX,
                file_monitor=file_monitor)


def check_attr_error(attr='', file_monitor=None, timeout=T_5):
    """Check if syscollector shows an error when using an invalid value in an attribute.

    Args:
        attr (str): attribute that contains the error.
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        timeout (str): timeout to check the event in Wazuh log
    """
    callback = f"ERROR: Invalid content for attribute '{attr}' at module 'syscollector'."
    check_event(callback=callback, timeout=timeout, prefix=WMODULES_SYSCOLLECTOR_PREFIX, file_monitor=file_monitor)
