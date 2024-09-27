# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Script to monitor Wazuh central components disk usage."""


import argparse
import logging
from datetime import datetime
from os import makedirs
from os.path import join
from signal import SIGINT, SIGTERM, signal
from tempfile import gettempdir
from time import sleep, time_ns
from types import FrameType
from typing import Dict, Optional

from process_resource_monitoring._logger import logger
from process_resource_monitoring.disk_usage_tracker import DiskUsageTracker

# Constant variables
METRICS_FOLDER: str = join(gettempdir(), 'process_metrics')
CURRENT_SESSION: str = join(METRICS_FOLDER, datetime.now().strftime('%d-%m-%Y'), str(time_ns() // 10**9))

# Global variables
active_disk_trackers: Dict[str, DiskUsageTracker] = {}
session_active: bool = True


def get_script_arguments() -> argparse.Namespace:
    """Parse the arguments passed to the script.

    Returns:
        (argparse.Namespace): object containing the script options.
    """
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] files_list',
        description='Monitor the resource usage of files and directories in files_list',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        dest='disk_paths',
        type=str,
        nargs='+',
        action='store',
        help='Paths of the files/dirs to monitor their disk usage.',
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
        dest='disk_unit',
        default='GB',
        choices=['B', 'KB', 'MB', 'GB', 'TB'],
        type=str,
        help='Unit for the disk usage related values. Default \'GB\'',
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
        '--store-disk',
        dest='store_disk_path',
        action='store',
        default=f'{CURRENT_SESSION}/files',
        type=str,
        help=f'Path to store the CSVs with the disk usage data. Default: \'{METRICS_FOLDER}/<id>/files\'.\n'
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

    # Shutdown all disk trackers
    for tracker in active_disk_trackers.values():
        tracker.shutdown()

    logger.info('Process finished gracefully')


def check_monitors_health(options: argparse.Namespace) -> bool:
    """Write the collected data in a CSV file.

    Args:
        options (argparse.Namespace): object containing the script options.

    Returns:
        (bool): False if there were any errors. True otherwise.
    """
    healthy = True
    # Check health of disk trackers
    for path, tracker in active_disk_trackers.items():
        if tracker.is_event_set():
            logger.warning(f'Monitoring of {path} failed. Attempting to recreate DiskUsageTracker instance')

            try:
                # Recreate DiskUsageTracker instance
                tracker.shutdown()
                new_tracker = DiskUsageTracker(file_path=path, value_unit=options.disk_unit)
                new_tracker.start()
                active_disk_trackers[path] = new_tracker
            except Exception as e:
                healthy = False
                logger.warning(f'Could not recreate DiskUsageTracker instance for {path}: {e}')

    return healthy


def monitors_healthcheck(options: argparse.Namespace) -> None:
    """Check each monitor's health while the session is active.

    Args:
        options (argparse.Namespace): object containing the script options.
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

        sleep(options.healthcheck_time)


def main():
    """Create DiskUsageTracker instances and start monitoring."""
    # Execute `shutdown_threads` function whenever any of these signals are received externally (e.g. SIGINT=Ctrl+C)
    signal(SIGTERM, shutdown_threads)
    signal(SIGINT, shutdown_threads)

    options = get_script_arguments()

    makedirs(f'{CURRENT_SESSION}/files')
    logging.basicConfig(
        filename=join(METRICS_FOLDER, 'wazuh-disk-metrics.log'),
        filemode='a',
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y/%m/%d %H:%M:%S',
        level=logging.INFO,
    )

    # By default logger level is logging.INFO
    if options.debug:
        logger.setLevel(logging.DEBUG)

    logger.info(f'Started new session: {CURRENT_SESSION}')

    # Start monitoring for disk usage of files
    if options.disk_paths:
        for path in options.disk_paths:
            tracker = DiskUsageTracker(
                file_path=path,
                value_unit=options.disk_unit,
                time_step=options.sleep_time,
                dst_dir=options.store_disk_path,
            )
            tracker.start()
            active_disk_trackers[path] = tracker

    monitors_healthcheck(options)


if __name__ == '__main__':
    main()
