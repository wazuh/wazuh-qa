import argparse
import logging
from collections import defaultdict
from datetime import datetime
from os import makedirs
from os.path import join
from signal import signal, SIGTERM, SIGINT
from tempfile import gettempdir
from time import time, sleep

from wazuh_testing.tools.performance.binary import Monitor, logger

METRICS_FOLDER = join(gettempdir(), 'process_metrics')
CURRENT_SESSION = join(METRICS_FOLDER, datetime.now().strftime('%d-%m-%Y'), str(int(time())))
ACTIVE_MONITORS = defaultdict(list)
SESSION_ACTIVE = True


def shutdown_threads(signal_number, frame):
    logger.info('Attempting to shutdown all monitor threads')

    global SESSION_ACTIVE
    SESSION_ACTIVE = False

    # Shutdown all possible monitors
    for monitor in sum(ACTIVE_MONITORS.values(), []):
        monitor.shutdown()

    logger.info('Process finished gracefully')


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Wazuh processes metrics",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p', '--processes', dest='process_list', required=True, type=str, nargs='+', action='store',
                        help='Type the processes name to monitor separated by whitespace.')
    parser.add_argument('-s', '--sleep', dest='sleep_time', type=float, default=1, action='store',
                        help='Type the time in seconds between each entry.')
    parser.add_argument('-u', '--units', dest='data_unit', default='KB', choices=['B', 'KB', 'MB'],
                        help='Type unit for the bytes-related values. Default bytes.')
    parser.add_argument('-v', '--version', dest='version', default=None, help='Version of the binaries. Default none.')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', default=False,
                        help='Enable debug level logging.')
    parser.add_argument('-H', '--healthcheck-time', dest='healthcheck_time', action='store', default=10, type=int,
                        help='Time in seconds between each health check.')
    parser.add_argument('-r', '--retries', dest='health_retries', action='store', default=10, type=int,
                        help='Number of reconnection retries before aborting the monitoring process.')
    parser.add_argument('--store', dest='store_path', action='store', default=gettempdir(),
                        help=f"Path to store the CSVs with the data. Default {gettempdir()}.")

    return parser.parse_args()


def check_monitors_health(options):
    """Write the collected data in a CSV file.

    Args:
        options (argparse.Options): object containing the script options.

    Returns:
        bool: True if there were any errors. False otherwise.
    """
    healthy = True
    for process, monitors in ACTIVE_MONITORS.items():
        # Check if there is any unhealthy monitor
        if any(filter(lambda m: m.event.is_set(), monitors)):
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
                monitor = Monitor(process_name=p_name, pid=pid, value_unit=options.data_unit,
                                  time_step=options.sleep_time,
                                  version=options.version, dst_dir=options.store_path)
                monitor.start()

                try:
                    # Replace old monitors for new ones
                    ACTIVE_MONITORS[process][i] = monitor
                except IndexError:
                    ACTIVE_MONITORS[process].append(monitor)

    return healthy


def monitors_healthcheck(options):
    """Check each monitor's health while the session is active.

    Args:
        options (argparse.Options): object containing the script options.
    """
    errors = 0
    while SESSION_ACTIVE:
        if check_monitors_health(options):
            errors = 0
        else:
            errors += 1
            if errors >= options.health_retries:
                logger.error('Reached maximum number of retries. Aborting')
                exit(1)

        sleep(options.healthcheck_time)


def main():
    signal(SIGTERM, shutdown_threads)
    signal(SIGINT, shutdown_threads)

    options = get_script_arguments()

    makedirs(CURRENT_SESSION)
    logging.basicConfig(filename=join(METRICS_FOLDER, 'wazuh-metrics.log'), filemode='a',
                        format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y/%m/%d %H:%M:%S',
                        level=logging.INFO)
    options.debug and logger.setLevel(logging.DEBUG)
    logger.info(f'Started new session: {CURRENT_SESSION}')

    for process in options.process_list:
        # Launch a monitor for every possible child process
        for i, pid in enumerate(Monitor.get_process_pids(process)):
            p_name = process if i == 0 else f'{process}_child_{i}'
            monitor = Monitor(process_name=p_name, pid=pid, value_unit=options.data_unit, time_step=options.sleep_time,
                              version=options.version, dst_dir=options.store_path)
            monitor.start()
            ACTIVE_MONITORS[process].append(monitor)

    monitors_healthcheck(options)


if __name__ == '__main__':
    main()
