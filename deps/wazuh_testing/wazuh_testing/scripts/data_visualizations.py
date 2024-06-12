import argparse
from os import makedirs
from os.path import exists
from tempfile import gettempdir

from wazuh_testing.tools.performance.visualization import DataVisualizer


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Script to generate data visualizations",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-s', '--sources', dest='csv_list', required=True, type=str, nargs='+', action='store',
                        help='Paths to the CSV files separated by whitespace.')
    parser.add_argument('-t', '--target', dest='visualization_target', default='binary',
                        choices=['binary', 'analysis', 'remote', 'agent', 'logcollector', 'cluster', 'api', 'wazuhdb'],
                        help='Generate data visualizations for a specific target. Default binary.')
    parser.add_argument('-d', '--destination', dest='destination', default=gettempdir(),
                        help=f'Directory to store the images. Default {gettempdir()}')
    parser.add_argument('-n', '--name', dest='name', default=None,
                        help=f'Base name for the images. Default {None}.')
    parser.add_argument('-c', '--columns', dest='columns', default=None,
                        help=f'Path to Json with Columns to Plot. Default {None}.')

    return parser.parse_args()


def main():
    options = get_script_arguments()
    destination = options.destination

    if not exists(destination):
        makedirs(destination)
    dv = DataVisualizer(dataframes=options.csv_list, target=options.visualization_target,
                        compare=False, store_path=options.destination, base_name=options.name,
                        columns_path=options.columns)
    dv.plot()


if __name__ == '__main__':
    main()
