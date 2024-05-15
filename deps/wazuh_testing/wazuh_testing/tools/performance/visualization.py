from os.path import join
from re import sub
from tempfile import gettempdir

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from matplotlib.ticker import LinearLocator

BINARY_NON_PRINTABLE_HEADERS = ['PID', 'Daemon', 'Version']

ANALYSISD_CSV_HEADERS = {
    'decoded_events': {
        'title': 'Events decoded per queue',
        'columns': [
            'Decoded from azure', 'Decoded from ciscat', 'Decoded from command', 'Decoded from docker',
            'Decoded from logcollector eventchannel', 'Decoded from logcollector eventlog',
            'Decoded from logcollector macos','Decoded from logcollector others','Decoded from osquery',
            'Decoded from rootcheck','Decoded from sca','Decoded from syscheck','Decoded from syscollector',
            'Decoded from vulnerability','Decoded from agentd','Decoded from dbsync','Decoded from monitor',
            'Decoded from remote'
        ],
    },
    'dropped_events': {
        'title': 'Events dropped per queue',
        'columns': [
            'Dropped from azure', 'Dropped from ciscat', 'Dropped from command', 'Dropped from docker',
            'Dropped from logcollector eventchannel', 'Dropped from logcollector eventlog',
            'Dropped from logcollector macos', 'Dropped from logcollector others', 'Dropped from osquery',
            'Dropped from rootcheck', 'Dropped from sca', 'Dropped from syscheck', 'Dropped from syscollector',
            'Dropped from vulnerability', 'Dropped from agentd', 'Dropped from dbsync', 'Dropped from monitor',
            'Dropped from remote'
        ],
    },
    'events_decoded_per_second': {
        'title': 'Events decoded per second',
        'columns': [
            'EDPS from azure', 'EDPS from ciscat', 'EDPS from command', 'EDPS from docker',
            'EDPS from logcollector eventchannel', 'EDPS from logcollector eventlog', 'EDPS from logcollector macos',
            'EDPS from logcollector others', 'EDPS from osquery', 'EDPS from rootcheck', 'EDPS from sca',
            'EDPS from syscheck', 'EDPS from syscollector', 'EDPS from vulnerability', 'EDPS from agentd',
            'EDPS from dbsync', 'EDPS from monitor', 'EDPS from remote'
        ],
    },
    'alerts_info': {
        'title': 'Alerts and events info.',
        'columns': [
            'Events processed', 'Events received', 'Written alerts', 'Written firewall', 'Written fts'
        ],
    }
}
REMOTED_CSV_HEADERS = {
    'events_info': {'title': 'Events sent and count',
        'columns': [
            "Events count", "Control messages", "Discarded messages", "Queue usage",
            'Metrics-Bytes sent', 'Dequeued messages'
        ]
    },
    'queue_size': {
        'title': 'Queue status',
        'columns': [
            'Queue size', 'Queue usage'
        ]
    },
    'tcp_sessions': {
        'title': 'TCP sessions',
        'columns': [
            'TCP sessions'
        ]
    },
    'recv_bytes': {
        'title': 'Bytes received',
        'columns': [
            'Metrics-Bytes received'
        ]
    }
}
AGENTD_CSV_HEADERS = {
    'number_of_events_and_messages': {
        'title': 'Number of events and messages',
        'columns': [
            'Number of generated events', 'Number of messages', 'Number of events buffered'
        ]
    },
    'ack_and_keepalive': {
        'title': 'Last ACK and KeepAlive',
        'columns': [
            'Last ACK', 'Last Keepalive'
        ]
    }
}

LOGCOLLECTOR_CSV_HEADERS = {
    'events': {
        'title': 'Events generated',
        'columns': [
            'Events'
        ]
    },
    'bytes_sent': {
        'title': 'Bytes sent',
        'columns': [
            'Bytes'
        ]
    },
    'drops': {
        'title': 'Events dropped',
        'columns': [
            'Target Drops'
        ]
    },
}

WAZUHDB_CSV_HEADERS = {
    'database_queries_counts': {
        'title': 'Database queries counts',
        'columns': [
            'Received queries', 'Agent queries'
        ]
    },
    'agent_queries_breakdown': {
        'title': 'Agent Queries Breakdown',
        'columns': [
            'db-begin', 'db-close', 'db-commit', 'db-remove', 'db-sql', 'db-vacuum', 'db-get_fragmentation'
        ]
    }
}


class DataVisualizer:
    """Class that allows to visualize the data collected using the wazuh_metrics tool.

    Args:
        dataframes (list): list containing the paths.
        target (str): string to set the visualization type.
        compare (bool): boolean to compare the different datasets.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        x_ticks_granularity (string): granularity of the Timestamp. It is set by default to minutes.
        x_ticks_interval (int): interval of the x-label.
        base_name (str, optional): base name used to store the images.
    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        compare (bool): boolean to compare the different datasets.
        target (str): string to set the visualization type.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        x_ticks_granularity (string): granularity of the Timestamp. It is set by default to minutes.
        x_ticks_interval (int): interval of the x-label.
        base_name (str, optional): base name used to store the images.
    """
    def __init__(self, dataframes, target, compare=False, store_path=gettempdir(), x_ticks_granularity='minutes',
                 x_ticks_interval=1, base_name=None):
        self.dataframes_paths = dataframes
        self.dataframe = None
        self.compare = compare
        self.target = target
        self.store_path = store_path
        self._load_dataframes()
        self.x_ticks_granularity = x_ticks_granularity
        self.x_ticks_interval = x_ticks_interval
        self.base_name = base_name
        sns.set(rc={'figure.figsize': (26, 9)})

    @staticmethod
    def _color_palette(size):
        """Create a list of different colors.

        Args:
            size (int): number of elements.

        Returns:
            list: list of colors. The colors are represented as a tuple of float values.
        """
        return sns.hls_palette(size if size > 1 else 1, h=.5)

    def _load_dataframes(self):
        """Load the dataframes from dataframes_paths."""
        for df_path in self.dataframes_paths:
            if self.dataframe is None and self.target != 'cluster':
                self.dataframe = pd.read_csv(df_path, index_col="Timestamp", parse_dates=True)
            else:
                new_csv = pd.read_csv(df_path, index_col="Timestamp", parse_dates=True)
                self.dataframe = pd.concat([self.dataframe, new_csv])

    def _set_x_ticks_interval(self, ax):
        """Set the number of labels that will appear in the X axis and their format.

        Args:
            ax (axes.SubplotBase): subplot base where the data will be printed.
        """
        if self.x_ticks_granularity == 'seconds':
            ax.xaxis.set_major_locator(LinearLocator(30))
        elif self.x_ticks_granularity == 'minutes':
            ax.xaxis.set_major_locator(LinearLocator(30))
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

    @staticmethod
    def _get_statistics(df, calculate_mean=True, calculate_median=False):
        """Function for calculating statistics.

        Args:
            df (pandas.DataFrame): dataframe on which the operations will be applied.
            calculate_mean (bool, optional): specify whether or not the mean will be calculated.
            calculate_median (bool, optional): specify whether or not the median will be calculated.
        """
        statistics = str()
        if calculate_mean:
            statistics += f"Mean: {round(pd.DataFrame.mean(df), 3)}\n"
        if calculate_median:
            statistics += f"Median: {round(pd.DataFrame.median(df), 3)}\n"

        return statistics

    @staticmethod
    def _basic_plot(ax, dataframe, label=None, color=None):
        """Basic function to visualize a dataframe.

        Args:
            ax (axes.SubplotBase): subplot base where the data will be printed.
            dataframe (pandas.Dataframe): dataframe containing the data from the CSVs.
            label (str, optional): optional label to add to the plot.
            color (tuple, optional): tuple defining the color (float, float).
        """
        ax.plot(dataframe, label=label, color=color)

    def _save_custom_plot(self, ax, y_label, title, rotation=90, cluster_log=False, statistics=None):
        """Function to add info to the plot, the legend and save the SVG image.

        Args:
            ax (axes.SubplotBase): subplot base where the data will be printed.
            y_label (str): label for the Y axis.
            title (str): title of the plot.
            rotation (int, optional): optional int to set the rotation of the X-axis labels.
            cluster_log (bool, optional): optional flag used to plot specific graphics for the cluster.
            statistics (str, optional): optional statistics measures.
        """
        if statistics:
            ax.text(0.9, 0.9, statistics, fontsize=14, transform=plt.gcf().transFigure)

        ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
        ax.set_ylabel(y_label)
        ax.set_title(title)

        if not cluster_log:
            self._set_x_ticks_interval(ax)
            plt.xticks(rotation=rotation)
            svg_name = sub(pattern=r'\(.*\)', string=y_label, repl='')
        else:
            svg_name = sub(pattern=r'\(.*\)', string=title, repl='')

        if self.base_name is not None:
            svg_name = f"{self.base_name}_{svg_name}"
        plt.savefig(join(self.store_path, f"{svg_name}.svg"), dpi=1200, format='svg')

    def _plot_data(self, elements, title=None, generic_label=None):
        """Function to plot the different types of dataframes.

        Args:
            elements (list, pandas.columns): columns to plot.
            title (str, optional): title of the plot.
            generic_label (str, optional): set a generic label to plot all the columns.
        """
        if self.target == 'binary':
            for element in elements:
                fig, ax = plt.subplots()
                daemons = self._get_daemons()
                colors = self._color_palette(len(daemons))
                for daemon, color in zip(daemons, colors):
                    self._basic_plot(ax, self.dataframe[self.dataframe.Daemon == daemon][element],
                                     label=daemon, color=color)
                self._save_custom_plot(ax, element, f"{element} {title}")

        elif self.target == 'logcollector':
            for element in elements:
                fig, ax = plt.subplots()
                targets = self._get_logcollector_targets()
                colors = self._color_palette(len(targets))
                for target, color in zip(targets, colors):
                    self._basic_plot(ax, self.dataframe[self.dataframe.Target == target][element],
                                     label=target, color=color)
                self._save_custom_plot(ax, element, title)

        elif self.target == 'cluster':
            for element in elements:
                fig, ax = plt.subplots()
                nodes = self.dataframe[self.dataframe.activity == element]['node_name'].unique()
                current_df = self.dataframe[self.dataframe.activity == element]
                current_df.reset_index(drop=True, inplace=True)
                for node, color in zip(nodes, self._color_palette(len(nodes))):
                    self._basic_plot(ax=ax, dataframe=current_df[current_df.node_name == node]['time_spent(s)'],
                                     label=node, color=color)
                self._save_custom_plot(ax, 'time_spent(s)', element.replace(' ', '_').lower(), cluster_log=True,
                                       statistics=DataVisualizer._get_statistics(
                                           current_df['time_spent(s)'], calculate_mean=True, calculate_median=True))

        elif self.target == 'api':
            for element in elements:
                fig, ax = plt.subplots()
                queries = self.dataframe.endpoint.unique()
                colors = self._color_palette(len(queries))
                for endpoint, color in zip(queries, colors):
                    self._basic_plot(ax, self.dataframe[self.dataframe.endpoint == endpoint]['time_spent(s)'],
                                     label=endpoint, color=color)
                self._save_custom_plot(ax, element, 'API Response time')

        else:
            fig, ax = plt.subplots()
            colors = self._color_palette(len(elements))
            for element, color in zip(elements, colors):
                self._basic_plot(ax, self.dataframe[element], label=element, color=color)
            self._save_custom_plot(ax, generic_label, title)

    def _plot_binaries_dataset(self):
        """Function to plot the hardware data of the binary."""
        elements = self.dataframe.columns.drop(BINARY_NON_PRINTABLE_HEADERS)
        self._plot_data(elements, title="usage during the test")

    def _plot_analysisd_dataset(self):
        """Function to plot the statistics from wazuh-analysisd."""
        for element in ANALYSISD_CSV_HEADERS:
            columns = ANALYSISD_CSV_HEADERS[element]['columns']
            title = ANALYSISD_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, title=title, generic_label=element)

    def _plot_remoted_dataset(self):
        """Function to plot the statistics from wazuh-remoted."""
        for element in REMOTED_CSV_HEADERS:
            columns = REMOTED_CSV_HEADERS[element]['columns']
            title = REMOTED_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, title=title, generic_label=element)

    def _plot_agentd_dataset(self):
        """Function to plot the statistics from wazuh-agentd."""
        if 'diff_seconds' not in self.dataframe.columns:
            self.dataframe['diff_seconds'] = abs(pd.to_datetime(self.dataframe['last_keepalive']) -
                                                 pd.to_datetime(self.dataframe['last_ack']))
            self.dataframe['diff_seconds'] = self.dataframe.diff_seconds.dt.total_seconds()

        for element in AGENTD_CSV_HEADERS:
            columns = AGENTD_CSV_HEADERS[element]['columns']
            title = AGENTD_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, title=title, generic_label=element)

    def _plot_logcollector_dataset(self):
        """Function to plot the statistics from a single file of logcollector."""
        for element in LOGCOLLECTOR_CSV_HEADERS:
            columns = LOGCOLLECTOR_CSV_HEADERS[element]['columns']
            title = LOGCOLLECTOR_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, title=title, generic_label=element)

    def _plot_cluster_dataset(self):
        """Function to plot the information from the cluster.log file."""
        self._plot_data(elements=list(self.dataframe['activity'].unique()), generic_label='Managers')

    def _plot_api_dataset(self):
        """Function to plot the information from the api.log file."""
        self._plot_data(elements=['endpoint'], generic_label='Queries')

    def _plot_wazuhdb_dataset(self):
        """Function to plot the statistics from wazuh-wazuhdb."""
        for element in WAZUHDB_CSV_HEADERS:
            columns = WAZUHDB_CSV_HEADERS[element]['columns']
            title = WAZUHDB_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, title=title, generic_label=element)

    def plot(self):
        """Public function to plot the dataset."""
        if self.target == 'binary':
            self._plot_binaries_dataset()
        elif self.target == 'analysis':
            self._plot_analysisd_dataset()
        elif self.target == 'remote':
            self._plot_remoted_dataset()
        elif self.target == 'agent':
            self._plot_agentd_dataset()
        elif self.target == 'logcollector':
            self._plot_logcollector_dataset()
        elif self.target == 'cluster':
            self._plot_cluster_dataset()
        elif self.target == 'api':
            self._plot_api_dataset()
        elif self.target == 'wazuhdb':
            self._plot_wazuhdb_dataset()
        else:
            raise AttributeError(f"Invalid target {self.target}")

    def _get_daemons(self):
        """Get the list of Wazuh Daemons in the dataset."""
        return self.dataframe.Daemon.unique()

    def _get_logcollector_targets(self):
        """Get the list of unique logcollector targets (sockets) in the dataset."""
        return self.dataframe.Target.unique()
