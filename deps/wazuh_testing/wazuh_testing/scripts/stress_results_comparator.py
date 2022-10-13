import argparse
import os
import logging
import sys
import warnings
import datetime
import pandas as pd
import matplotlib.pyplot as plt
from prettytable import PrettyTable

"""
Version: 1.0
Tool documentation: https://github.com/wazuh/wazuh-qa/wiki/Stress-results-comparator-tool
Description: Tool to compare >=2 stress results CSV data files and generate plots for the specified stats.
"""

LOGGER = logging.getLogger('stress_comparator')
AGENT_DAEMON_LIST = ['agentd', 'logcollector', 'syscheckd', 'modulesd', 'execd', 'agent.exe']
MANAGER_DAEMON_LIST = ['remoted', 'analysisd', 'wazuh-db', 'wazuh-authd', 'clusterd', 'monitord',
                       'integratord', 'maild', 'logcollector', 'syscheckd', 'modulesd', 'execd']
DAEMON_LIST = list(set(AGENT_DAEMON_LIST + MANAGER_DAEMON_LIST))
STATS_MAPPING = {
    'cpu': 'CPU(%)',
    'memory': 'RSS(KB)',
    'disk_read': 'Disk_Read(B)',
    'disk_written': 'Disk_Written(B)',
    'virtual_memory': 'VMS(KB)',
    'file_descriptor': 'FD',
    'read_ops': 'Read_Ops',
    'write_ops': 'Write_Ops',
    'disk_usage': 'Disk(%)',
    'uss': 'USS(KB)',
    'pss': 'PSS(KB)',
    'swap': 'SWAP(KB)',
    'remoted_queue_size': 'Queue size',
    'remoted_total_queue_size': 'Total Queue size',
    'remoted_tcp_sessions': 'TCP sessions',
    'remoted_events_count': 'Events count',
    'remoted_control_messages': 'Control messages',
    'remoted_discarded_messages': 'Discarded messages',
    'remoted_messages_sent': 'Messages sent',
    'remoted_bytes_received': 'Bytes received',
    'analysisd_total_events': 'Total Events',
    'analysisd_syscheck_events_decoded': 'Syscheck Events Decoded',
    'analysisd_syscheck_edps': 'Syscheck EDPS',
    'analysisd_syscollector_events_decoded': 'Syscollector Events Decoded',
    'analysisd_syscollector_edps': 'Syscollector EDPS',
    'analysisd_rootcheck_events_decoded': 'Rootcheck Events Decoded',
    'analysisd_rootcheck_edps': 'Rootcheck EDPS',
    'analysisd_sca_events_decoded': 'SCA Events Decoded',
    'analysisd_sca_edps': 'SCA EDPS',
    'analysisd_hostinfo_events_decoded': 'HostInfo Events Decoded',
    'analysisd_hostinfo_edps': 'HostInfo EDPS',
    'analysisd_winevt_events_decoded': 'WinEvt Events Decoded',
    'analysisd_winevt_edps': 'WinEvt EDPS',
    'analysisd_other_events_decoded': 'Other Events Decoded',
    'analysisd_other_edps': 'Other EDPS',
    'analysisd_events_processed': 'Events processed (Rule matching)',
    'analysisd_events_edps': 'Events EDPS (Rule matching)',
    'analysisd_events_received': 'Events received',
    'analysisd_events_dropped': 'Events dropped',
    'analysisd_syscheck_queue': 'Syscheck queue',
    'analysisd_syscollector_queue': 'Syscollector queue',
    'analysisd_rootcheck_queue': 'Rootcheck queue',
    'analysisd_sca_queue': 'SCA queue',
    'analysisd_hostinfo_queue': 'Hostinfo queue',
    'analysisd_winevt_queue': 'Winevt queue',
    'analysisd_event_queue': 'Event queue',
    'analysisd_rule_matching_queue': 'Rule matching queue',
    'analysisd_alerts_log_queue': 'Alerts log queue',
    'analysisd_firewall_log_queue': 'Firewall log queue',
    'analysisd_statistical_log_queue': 'Statistical log queue',
    'analysisd_archives_log_queue': 'Archives log queue',
    'analysisd_alerts_written': 'Alerts written',
    'analysisd_firewall_alerts_written': 'Firewall alerts written',
    'analysisd_fts_alerts_written': 'FTS alerts written',
    'agentd_status': 'Status',
    'agentd_last_keepalive': 'Last Keepalive',
    'agentd_last_ack': 'Last ACK',
    'agentd_generated_events_number': 'Number of generated events',
    'agentd_messages_number': 'Number of messages',
    'agentd_buffered_events_number': 'Number of events buffered',
}
ALLOWED_STATS = list(STATS_MAPPING.keys())


def set_logging(debug=False):
    """Configure the script logging.

    Args:
        debug (boolean): True for DEBUG level, False otherwise
    """
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))
    LOGGER.addHandler(handler)


def get_parameters():
    """Get and process script parameters.

    Returns:
        argparse.Namespace: Script parameters.
    """
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-d', '--daemon', metavar='<daemon>', type=str,
                            help='Daemon to select and compare', required=True,
                            choices=DAEMON_LIST, dest='selected_daemon')

    arg_parser.add_argument('-f', '--files', metavar='<files>', type=str, nargs='+', action='store',
                            help='Data files to compare', required=True, dest='data_sources')

    arg_parser.add_argument('-l', '--labels', metavar='<sources>', type=str, nargs='+', action='store',
                            help='Labels to assign to each data file', required=True, dest='labels')

    arg_parser.add_argument('-s', '--stats', metavar='<stats>', type=str, nargs='+', action='store',
                            choices=ALLOWED_STATS, help='Stats to compare', default=['cpu', 'memory'],
                            dest='stats_to_compare')

    arg_parser.add_argument('-o', '--output', metavar='<output>', type=str,
                            help='Output path to save plot files. Default script path', dest='output_path')

    arg_parser.add_argument('--force', action='store_true',
                            help='Force comparison of data even though they have different numbers of rows. The first '
                                 'n data will be compared, where n is the total number of rows of the smallest data '
                                 'file.')

    arg_parser.add_argument('-p', '--plots', action='store_true', help='Generate comparing charts')

    arg_parser.add_argument('--debug', action='store_true', help='Activate debug logging')

    return arg_parser.parse_args()


def get_dataframe_from_file(data_source):
    """Read the CSV and convert it to dataframe

    Args:
        data_source (str): Data source file path.

    Returns:
        DataFrame: dataframe object.
    """
    return pd.read_csv(data_source)


def raise_error(message):
    """Raise a custom error

    Args:
        message (str): Error message
    """
    LOGGER.error(f"\033[1;31;40m{message}\033[0m")
    sys.exit(1)


def validate_parameters(parameters):
    """Validate the input parameters

    Args:
        parameters (argparse.Namespace): Script parameters.
    """
    # Check that the number of data_sources and labels parameters are the same
    if len(parameters.data_sources) != len(parameters.labels):
        raise_error('The number of --labels parameter values must be equal to --sources')

    files_length = []
    # Iterate over each data source file to check that it exists and it has more than 0 rows
    for data_source in parameters.data_sources:
        # Check that the source file exists
        if not os.path.exists(data_source):
            raise_error(f"The source '{data_source}' does not exist")
        dataframe = get_dataframe_from_file(data_source)
        data_length = len(dataframe)
        # Check that the source file has more than 0 rows
        if data_length == 0:
            raise_error(f"The source '{data_source}' has not data rows or it has not CSV format")
        else:
            files_length.append(data_length)

        # Check that the selected stats are present in all source files
        for stat in parameters.stats_to_compare:
            if STATS_MAPPING[stat] not in dataframe.columns:
                raise_error(f"Can not obtain the {stat} stat in {data_source} due to {STATS_MAPPING[stat]} does not "
                            'exist')

    # Check that all source files have the same rows number
    if not parameters.force and len(list(set(files_length))) > 1:
        message = '\n'.join([f"    - {parameters.data_sources[index]}: {rows} rows" for index, rows
                             in enumerate(files_length)])
        raise_error(f"The source files have different number of rows:\n{message}")


def process_dataframes(parameters):
    """Read and process data sources according to the specified parameters

    Args:
        parameters (argparse.Namespace): Script parameters.

    Returns:
        list(DataFrame): dataframe object list.
    """
    # Read the dataframe and filter it only with selected daemon
    dataframes = [pd.read_csv(source_file) for source_file in parameters.data_sources]
    filtered_dataframes = [dataframe[dataframe['Daemon'] == f"wazuh-{parameters.selected_daemon}"] for dataframe
                           in dataframes]

    # Check that dataframes have rows after filtering. If not, it means that the dataset has not conmon data
    for index, dataframe in enumerate(filtered_dataframes):
        if dataframe.empty:
            raise_error(f"{parameters.data_sources[index]} has not {parameters.selected_daemon} values")

    # Reduce the dataframes to the minimum number of rows according to the smallest of them all (to compare them)
    if parameters.force:
        min_rows = min([len(dataframe) for dataframe in filtered_dataframes])

        for index, (dataframe, source_file) in enumerate(zip(filtered_dataframes, parameters.data_sources)):
            LOGGER.info(f"Reducing dataframe from {source_file}: before {len(dataframe)} --> after {min_rows} rows")
            filtered_dataframes[index] = filtered_dataframes[index].head(min_rows)

    return filtered_dataframes


def print_dataframes_stats(dataframes, parameters):
    for stat in parameters.stats_to_compare:
        table = PrettyTable()
        table.title = STATS_MAPPING[stat]
        table.field_names = ['Name', 'Mean', 'Max value', 'Min value']
        for index, dataframe in enumerate(dataframes):
            table.add_row([parameters.labels[index], round(dataframe[STATS_MAPPING[stat]].mean(), 1),
                           dataframe[STATS_MAPPING[stat]].max(), dataframe[STATS_MAPPING[stat]].min()])
        print(table)


def generate_plots(dataframes, parameters):
    """Generate the plots and save them in figures/images

    Args:
        parameters (argparse.Namespace): Script parameters.
    """
    date_time = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_path = parameters.output_path if parameters.output_path else os.getcwd()

    # Create output path if not exists
    if not os.path.exists(output_path):
        LOGGER.info(f"{output_path} does not exist, creating it ...")
        os.makedirs(output_path, exist_ok=True)

    # For each selected stat, generate a comparison figure
    for stat in parameters.stats_to_compare:
        for index, dataframe in enumerate(dataframes):
            # Add a new ID column to the dataframe. It will be used for x axis values
            dataframe['id'] = dataframe.reset_index().index
            plt.plot(dataframe['id'], dataframe[STATS_MAPPING[stat]], label=parameters.labels[index],
                     linewidth=1)

        # Configure plot settings
        plt.xticks(rotation=90, fontsize=6)
        plt.margins(0.01, 0.01)
        plt.xlabel('ID')
        plt.ylabel(STATS_MAPPING[stat])
        plt.title(f"{STATS_MAPPING[stat]}", fontsize=20)
        plt.legend()
        plt.tight_layout()

        file_name = os.path.join(output_path, f"{date_time}_{stat}_comparison.png")
        LOGGER.info(f"Generating {file_name} plot ...")

        # Generate the figure
        plt.savefig(file_name, dpi=1200, format='png')
        # Clean plots for the next iteration
        plt.clf()


def main():
    """Main process for generating plots according to the user input parameters"""
    warnings.filterwarnings('ignore')
    parameters = get_parameters()
    set_logging(parameters.debug)
    validate_parameters(parameters)
    dataframes = process_dataframes(parameters)
    print_dataframes_stats(dataframes, parameters)

    if parameters.plots:
        generate_plots(dataframes, parameters)


if __name__ == '__main__':
    main()
