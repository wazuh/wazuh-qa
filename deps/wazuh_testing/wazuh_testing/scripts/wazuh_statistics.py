import argparse
import logging
from datetime import datetime
from os import makedirs
from os.path import join
from signal import signal, SIGTERM, SIGINT
from tempfile import gettempdir
from time import time

from wazuh_testing.tools.performance.statistic import StatisticMonitor, logger

METRICS_FOLDER = join(gettempdir(), 'wazuh_statistics')
CURRENT_SESSION = join(METRICS_FOLDER, datetime.now().strftime('%d-%m-%Y'), str(int(time())))
MONITOR_LIST = []


def shutdown_threads(signal_number, frame):
    logger.info('Attempting to shutdown all monitor threads')
    for monitor in MONITOR_LIST:
        monitor.shutdown()
    logger.info('Process finished')


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Wazuh statistics collector",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--target', dest='target_list', required=True, type=str, nargs='+', action='store',
                        help='Type the statistics target to collect separated by whitespace. '
                             'Targets: agent, logcollector, remote, analysis and wazuhdb')
    parser.add_argument('-s', '--sleep', dest='sleep_time', type=float, default=5, action='store',
                        help='Type the time in seconds between each entry.')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', default=False,
                        help='Enable debug level logging.')
    parser.add_argument('--store', dest='store_path', action='store', default=gettempdir(),
                        help=f"Path to store the CSVs with the data. Default {gettempdir()}.")
    parser.add_argument('-u', '--use_state_file', action='store_true', default=False,
                        help="Use state files for analysis and remote operations. "
                             "When used with 'remote' and 'analysis', data will be collected from state files; "
                             "otherwise, the API will be used. Default False")
    parser.add_argument('-i', '--ip', dest='ip', action='store', default='localhost',
                        help=f"Specify the IP address for the API. Default is 'localhost'")
    parser.add_argument('-p', '--port', dest='port', action='store', default='55000',
                        help=f"Specify the port for the API. Default is '55000'")

    return parser.parse_args()


def main():
    signal(SIGTERM, shutdown_threads)
    signal(SIGINT, shutdown_threads)

    options = get_script_arguments()

    makedirs(CURRENT_SESSION)
    logging.basicConfig(filename=join(METRICS_FOLDER, 'wazuh-statistics.log'), filemode='a',
                        format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y/%m/%d %H:%M:%S',
                        level=logging.INFO)
    options.debug and logger.setLevel(logging.DEBUG)
    logger.info(f'Started new session: {CURRENT_SESSION}')

    for target in options.target_list:
        monitor = StatisticMonitor(target=target, time_step=options.sleep_time, dst_dir=options.store_path,
                                   use_state_file=options.use_state_file, ip=options.ip, port=options.port)
        MONITOR_LIST.append(monitor)
        monitor.start()


if __name__ == '__main__':
    main()