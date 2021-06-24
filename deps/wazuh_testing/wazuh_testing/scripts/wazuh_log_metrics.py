import argparse
from datetime import datetime
from os.path import join
from tempfile import gettempdir
from time import time

from wazuh_testing.tools.performance.binary import ClusterLogParser, APILogParser

METRICS_FOLDER = join(gettempdir(), 'log_metrics')
CURRENT_SESSION = join(METRICS_FOLDER, datetime.now().strftime('%d-%m-%Y'), str(int(time())))


def get_script_arguments():
    target_choices = ['cluster', 'api']
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Wazuh log parser",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-l', '--log', dest='log', default=None,
                        help='Log file to be analyzed.', action='store')
    parser.add_argument('-t', '--target', dest='log_type_target', default='cluster',
                        choices=target_choices, help='Log type to be parsed. Default cluster.')
    parser.add_argument('-o', '--output', dest='output', action='store', default=None,
                        help='Folder where the extracted data will be dumped (csv).')

    return parser.parse_args()


def main():
    options = get_script_arguments()

    if options.log and options.log_type_target:
        if options.log_type_target == 'cluster':
            ClusterLogParser(log_file=options.log, dst_dir=options.output).write_csv()
        elif options.log_type_target == 'api':
            APILogParser(log_file=options.log, dst_dir=options.output).write_csv()


if __name__ == '__main__':
    main()
