import argparse
import logging
from datetime import datetime
from os import makedirs
from os.path import join
from signal import signal, SIGTERM, SIGINT
from tempfile import gettempdir
from time import time

from wazuh_testing.tools.performance.binary import Monitor, logger

METRICS_FOLDER = join(gettempdir(), 'process_metrics')
CURRENT_SESSION = join(METRICS_FOLDER, datetime.now().strftime('%d-%m-%Y'), str(int(time())))
MONITOR_LIST = []


def shutdown_threads(signal_number, frame):
    logger.info('Attempting to shutdown all monitor threads')
    for monitor in MONITOR_LIST:
        monitor.shutdown()
    logger.info('Process finished')


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
    parser.add_argument('--store', dest='store_path', action='store', default=gettempdir(),
                        help=f"Path to store the CSVs with the data. Default {gettempdir()}")

    return parser.parse_args()


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
        monitor = Monitor(process_name=process, value_unit=options.data_unit, time_step=options.sleep_time,
                          version=options.version, dst_dir=options.store_path)
        monitor.start()
        MONITOR_LIST.append(monitor)


if __name__ == '__main__':
    main()
