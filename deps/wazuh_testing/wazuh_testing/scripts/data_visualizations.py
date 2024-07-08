import argparse
from os import makedirs
from os.path import exists
from tempfile import gettempdir

from wazuh_testing.tools.performance.visualization import (
    BinaryDatavisualizer,
    ClusterStatisticsVisualizer,
    DaemonStatisticsVisualizer,
    IndexerAlerts,
    IndexerVulnerabilities,
    LogcollectorStatisticsVisualizer,
)

supported_targets = ['binary', 'analysis', 'remote', 'wazuhdb', 'logcollector',
                     'cluster', 'indexer-alerts',
                     'indexer-vulnerabilities']
daemon_supported_statistics = ['analysis', 'remote', 'wazuhdb']
strategy_plot_by_target = {
    'binary': BinaryDatavisualizer,
    'daemon-statistics': DaemonStatisticsVisualizer,
    'cluster': ClusterStatisticsVisualizer,
    'logcollector': LogcollectorStatisticsVisualizer,
    'indexer-alerts': IndexerAlerts,
    'indexer-vulnerabilities': IndexerVulnerabilities
}


def create_destination_directory(destination_directory):
    if not exists(destination_directory):
        makedirs(destination_directory)


def validate_arguments(options):
    if options.visualization_target != 'binary' and options.unify:
        raise ValueError('Unify option is not allowed for non binary data plotting')


def get_script_arguments():
    parser = argparse.ArgumentParser(usage='%(prog)s [options]', description='Script to generate data visualizations',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-s', '--sources', dest='csv_list', required=True, type=str, nargs='+', action='store',
                        help='Paths to the CSV files separated by whitespace.')
    parser.add_argument('-t', '--target', dest='visualization_target', default='binary',
                        choices=supported_targets,
                        help='Generate data visualizations for a specific target. Default binary.')
    parser.add_argument('-d', '--destination', dest='destination', default=gettempdir(),
                        help=f'Directory to store the images. Default {gettempdir()}')
    parser.add_argument('-n', '--name', dest='name', default=None,
                        help=f'Base name for the images. Default {None}.')
    parser.add_argument('-c', '--columns', dest='columns', default=None,
                        help=f'Path to Json with Columns to Plot. Default {None}.')
    parser.add_argument('-u', '--unify', dest='unify', action='store_true',
                        help='Unify data of the binary processes with their subprocesses to plot.')

    return parser.parse_args()


def main():
    options = get_script_arguments()
    create_destination_directory(options.destination)

    target = options.visualization_target
    validate_arguments(options)

    visualization_options = {
        'dataframes_paths': options.csv_list,
        'store_path': options.destination,
        'base_name': options.name
    }

    strategy = target
    if target in daemon_supported_statistics:
        visualization_options['daemon'] = target
        strategy = 'daemon-statistics'
    elif target == 'binary':
        visualization_options['unify_child_daemon_metrics'] = options.unify

    dv = strategy_plot_by_target[strategy](**visualization_options)

    dv.plot()


if __name__ == '__main__':
    main()
