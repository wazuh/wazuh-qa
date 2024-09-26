# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Script to monitor Wazuh central components processes resource usage."""


import argparse
import logging
from collections import defaultdict
from datetime import datetime
from os import makedirs
from os.path import join
from signal import SIGINT, SIGTERM, signal
from tempfile import gettempdir
from time import sleep, time_ns
from types import FrameType
from typing import Dict, List, Optional, Set

from process_resource_monitoring._logger import logger
from process_resource_monitoring.monitor import Monitor

# Constant variables
METRICS_FOLDER: str = join(gettempdir(), 'process_metrics')
CURRENT_SESSION: str = join(METRICS_FOLDER, datetime.now().strftime('%d-%m-%Y'), str(time_ns() // 10**9))
PROCESS_MAPPING: Dict[str, str] = {
    # Manager processes
    'agentlessd': 'wazuh-agentlessd',
    'analysisd': 'wazuh-analysisd',
    'apid': 'wazuh_apid.py',
    'authd': 'wazuh-authd',
    'clusterd': 'wazuh_clusterd.py',
    'csyslogd': 'wazuh-csyslogd',
    'db': 'wazuh-db',
    'dbd': 'wazuh-dbd',
    'execd': 'wazuh-execd',
    'integratord': 'wazuh-integratord',
    'logcollector': 'wazuh-logcollector',
    'maild': 'wazuh-maild',
    'modulesd': 'wazuh-modulesd',
    'monitord': 'wazuh-monitord',
    'remoted': 'wazuh-remoted',
    'wazuh-syscheckd': 'syscheckd',

    # Indexer
    'indexer': 'wazuh-indexer',

    # Dashboard
    'dashboard': 'wazuh-dashboard',

    # Agent
    'agentd': 'wazuh-agentd',
}

# Global variables
active_monitors: Dict[str, List[Monitor]] = defaultdict(list)
processes_pids: Set[int] = set()
session_active: bool = True


def get_script_arguments() -> argparse.Namespace:
    """Parse the arguments passed to the script.

    Returns:
        (argparse.Namespace): object containing the script options.
    """
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] process_list',
        description='Monitor the resource usage of processes in process_list',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        dest='process_name_list',
        type=str,
        nargs='+',
        choices=list(PROCESS_MAPPING.keys()),
        action='store',
        help='Name of process/processes to monitor separated by whitespace.',
    )
    parser.add_argument(
        '-s',
        '--sleep',
        dest='sleep_time',
        default=1.0,
        type=float,
        action='store',
        help='Time in seconds between each entry. Default: 1.0.',
    )
    parser.add_argument(
        '-u',
        '--units',
        dest='data_unit',
        default='KB',
        choices=['B', 'KB', 'MB'],
        type=str,
        help='Unit for the bytes-related values. Default: \'KB\'.',
    )
    parser.add_argument(
        '-v',
        '--version',
        dest='version',
        default=None,
        type=str,
        help='Version of the binaries. Default: None.',
    )
    parser.add_argument(
        '-d',
        '--debug',
        dest='debug',
        action='store_true',
        default=False,
        help='Enable debug level logging. Default: False.',
    )
    parser.add_argument(
        '-H',
        '--healthcheck-time',
        dest='healthcheck_time',
        action='store',
        default=10,
        type=int,
        help='Time in seconds between each health check. Default: 10.',
    )
    parser.add_argument(
        '-r',
        '--retries',
        dest='health_retries',
        action='store',
        default=10,
        type=int,
        help='Number of reconnection retries before aborting the monitoring process. Default: 10.',
    )
    parser.add_argument(
        '--store-process',
        dest='store_process_path',
        action='store',
        default=CURRENT_SESSION,
        type=str,
        help=f'Path to store the CSVs with the process resource usage data. Default: \'{METRICS_FOLDER}/<id>\'.\n'
        + 'Where <id> is the number of seconds since the epoch when the monitoring started.',
    )

    return parser.parse_args()


def shutdown_threads(signal_number: int, frame: Optional[FrameType]) -> None:
    """Stop and close all monitoring threads.

    Args:
        signal_number (int): number of the signal.
        frame (FrameType, optional): frame of the object.
    """
    logger.info('Attempting to shutdown all monitor threads')

    global session_active
    session_active = False

    # Shutdown all possible monitors
    for monitor in sum(active_monitors.values(), []):
        monitor.shutdown()

    logger.info('Process finished gracefully')


def check_monitors_health(options) -> bool:
    """Write the collected data in a CSV file.

    Args:
        options (argparse.Options): object containing the script options.

    Returns:
        (bool): False if there were any errors. True otherwise.
    """
    healthy = True
    for process, monitors in active_monitors.items():
        # Check if there is any unhealthy monitor
        if any(filter(lambda monitor: monitor.is_event_set(), monitors)):
            logger.warning(f'Monitoring of {process} failed. Attempting to create new monitor instances')

            try:
                # Try to get new PIDs
                process_pids = Monitor.get_process_pids(process)
                # Shutdown all the related monitors to the failed process (necessary for multiprocessing)
                for monitor in monitors:
                    monitor.shutdown()
            except ValueError:
                healthy = False
                logger.warning(f'Could not create new monitor instances for {process}')
                continue

            for i, pid in enumerate(process_pids):
                # Attempt to create new monitor instances for the process
                p_name = process if i == 0 else f'{process}_child_{i}'
                monitor = Monitor(
                    process_name=p_name,
                    pid=pid,
                    value_unit=options.data_unit,
                    time_step=options.sleep_time,
                    version=options.version,
                    dst_dir=options.store_process_path,
                )
                monitor.start()

                try:
                    # Replace old monitors for new ones
                    active_monitors[process][i] = monitor
                except IndexError:
                    active_monitors[process].append(monitor)

    return healthy


def monitors_healthcheck(options, process_list) -> None:
    """Check each monitor's health while the session is active.

    Args:
        options (argparse.Options): object containing the script options.
        process_list (List[str]): list of the processes with monitors to be checked.
    """
    errors = 0
    while session_active:
        if check_monitors_health(options):
            errors = 0
        else:
            errors += 1
            if errors >= options.health_retries:
                logger.error('Reached maximum number of retries. Aborting')
                exit(1)

        # Periodically check for new processes that need to be monitored
        global processes_pids
        for process in process_list:
            try:
                # Get the current PIDs of the process
                current_pids = Monitor.get_process_pids(process)

                # Check for any new PIDs that are not already being monitored
                for pid in current_pids:
                    if pid not in processes_pids:
                        logger.info(f'New process {process} detected ({pid})')
                        processes_pids.add(pid)

                        # Start a new monitor for the detected process
                        p_name = f'{process}_{pid}'
                        monitor = Monitor(
                            process_name=p_name,
                            pid=pid,
                            value_unit=options.data_unit,
                            time_step=options.sleep_time,
                            version=options.version,
                            dst_dir=options.store_process_path,
                        )
                        monitor.start()
                        active_monitors[process].append(monitor)
            except ValueError:
                logger.warning(f'Could not create new monitor instances for {process}')

        sleep(options.healthcheck_time)


def main():
    """Create Monitor instances and start monitoring."""
    # Execute `shutdown_threads` function whenever any of these signals are received externally (e.g. SIGINT=Ctrl+C)
    signal(SIGTERM, shutdown_threads)
    signal(SIGINT, shutdown_threads)

    options = get_script_arguments()

    makedirs(CURRENT_SESSION)
    logging.basicConfig(
        filename=join(METRICS_FOLDER, 'wazuh-resource-metrics.log'),
        filemode='a',
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y/%m/%d %H:%M:%S',
        level=logging.INFO,
    )

    # By default logger level is logging.INFO
    if options.debug:
        logger.setLevel(logging.DEBUG)

    logger.info(f'Started new session: {CURRENT_SESSION}')

    # Start monitoring for processes
    process_list = list(map((lambda p: PROCESS_MAPPING[p]), options.process_name_list))
    global processes_pids
    for process in process_list:
        try:
            process_pids = Monitor.get_process_pids(process)
            # Launch a monitor for every possible child process
            # for i, pid in enumerate(Monitor.get_process_pids(process)):
            for i, pid in enumerate(process_pids):
                processes_pids.add(pid)
                p_name = process if i == 0 else f'{process}_child_{i}'
                monitor = Monitor(
                    process_name=p_name,
                    pid=pid,
                    value_unit=options.data_unit,
                    time_step=options.sleep_time,
                    version=options.version,
                    dst_dir=options.store_process_path,
                )
                monitor.start()
                active_monitors[process].append(monitor)
        except ValueError:
            logger.warning(f'Could not create initial monitor instances for {process}')


    monitors_healthcheck(options, process_list)


if __name__ == '__main__':
    main()
