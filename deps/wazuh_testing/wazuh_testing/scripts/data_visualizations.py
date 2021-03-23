import argparse
from os import makedirs
from os.path import exists
from wazuh_testing.tools.performance.visualization import DataVisualizer
from tempfile import gettempdir


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Script to generate data visualizations",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-s', '--sources', dest='csv_list', required=True, type=str, nargs='+', action='store',
                        help='Paths to the CSV files separated by whitespace.')
    parser.add_argument('-t', '--target', dest='visualization_target', default='binary',
                        choices=['binary', 'analysisd', 'remoted', 'agentd', 'logcollector'],
                        help='Generate data visualizations for a specific target. Default binary.')
    parser.add_argument('-d', '--destination', dest='destination', default=gettempdir(),
                        help=f'Directory to store the images. Default {gettempdir()}')

    return parser.parse_args()


def main():
    options = get_script_arguments()
    csv_list = options.csv_list
    target = options.visualization_target
    destination = options.destination

    if not exists(destination):
        makedirs(destination)
    dv = DataVisualizer(dataframes=csv_list, target=target, compare=False, store_path=destination)
    dv.plot()


if __name__ == '__main__':
    main()
