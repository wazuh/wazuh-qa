import json
from abc import ABC, abstractmethod
from os.path import dirname, join, realpath
from re import sub
from tempfile import gettempdir

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from matplotlib.ticker import LinearLocator


class DataVisualizer(ABC):
    """Class that allows to visualize the data collected using the wazuh_metrics tool.

    Args:
        dataframes_paths (list): list containing the paths.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
    """
    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        self.dataframes_paths = dataframes_paths
        self.store_path = store_path
        self.base_name = base_name
        self.dataframe = pd.DataFrame()

        self._load_dataframes()
        sns.set_theme(rc={'figure.figsize': (26, 9)})

    @abstractmethod
    def _get_expected_fields(self) -> list:
        pass

    @abstractmethod
    def plot(self) -> None:
        pass

    def _validate_dataframe(self) -> None:
        self._check_missing_mandatory_fields()
        self._check_no_duplicated()
        self._check_unexpected_values()

    def _check_no_duplicated(self):
        if self.dataframe.columns.duplicated().any():
            raise ValueError('Duplicate column names found in the CSV file.')

    def _check_missing_mandatory_fields(self):
        if not (self._get_expected_fields() == self._get_data_columns()):
            raise ValueError(f"Missing some of the mandatory values. Expected values: {self._get_expected_fields()}")

    def _check_unexpected_values(self):
        if not set(self._get_data_columns()).issubset(set(self._get_expected_fields())):
            raise ValueError('Column names do not match the expected metrics.')

    def _get_data_columns(self) -> list:
        try:
            return list(self.dataframe.columns)
        except StopIteration:
            return []

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
                new_csv = pd.read_csv(df_path, index_col="Timestamp", parse_dates=True)
                self.dataframe = pd.concat([self.dataframe, new_csv])

    def _set_x_ticks_interval(self, ax):
        """Set the number of labels that will appear in the X axis and their format.

        Args:
            ax (axes.SubplotBase): subplot base where the data will be printed.
        """
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



class BinaryDatavisualizer(DataVisualizer):
    binary_metrics_fields = ["Daemon", "Version", "PID",
                             "CPU", "VMS", "RSS", "USS",
                             "PSS", "SWAP", "FD", "Read_Ops",
                             "Write_Ops", "Disk_Read", "Disk_Written",
                             "Disk_Read_Speed", "Disk_Write_Speed"]

    def __init__(self, dataframes, store_path=gettempdir(), base_name=None):
        super().__init__(dataframes, store_path, base_name)
        self._validate_dataframe()

    def _get_expected_fields(self) -> list:
        return self.binary_metrics_fields

    def _normalize_column_name(self, column_name: str):
        if '(' in column_name:
            return column_name.split('(')[0].strip()
        return column_name

    def _get_data_columns(self):
        column_names = self.dataframe.columns
        normalized_columns = [self._normalize_column_name(col) for col in column_names.tolist()]

        return normalized_columns

    def _get_daemons(self):
        """Get the list of Wazuh Daemons in the dataset."""
        return self.dataframe.Daemon.unique()

    def _get_fields_to_plot(self):
        column_names = self.dataframe.columns
        fields_to_plot = []

        for field_to_plot in column_names:
            if self._normalize_column_name(field_to_plot) in self.binary_metrics_fields:
                fields_to_plot.append(field_to_plot)

        return fields_to_plot

    def plot(self):
        columns_to_plot = self._get_fields_to_plot()
        for element in columns_to_plot:
            _, ax = plt.subplots()
            daemons = self._get_daemons()
            colors = self._color_palette(len(daemons))
            for daemon, color in zip(daemons, colors):
                self._basic_plot(ax, self.dataframe[self.dataframe.Daemon == daemon][element],
                                label=daemon, color=color)

            self._save_custom_plot(ax, element, f"{element} {element}")



class DaemonStatisticsVisualizer(DataVisualizer):
    general_fields = ['API Timestamp', 'Interval (Timestamp-Uptime)', 'Events processed', 'Events received']
    statistics_plot_data_directory = join(dirname(realpath(__file__)), '..', '..', 'data', 'data_visualizer')
    statistics_filename_suffix = '_csv_headers.json'

    def __init__(self, dataframes, daemon, store_path=gettempdir(), base_name=None):
        self.daemon = daemon
        super().__init__(dataframes, daemon, store_path)
        self.plots_data = self._load_plot_data()
        self.expected_fields = []
        for graph in self.plots_data.values():
            for column in graph['columns']:
                self.expected_fields.append(column)
        self.expected_fields.extend(self.general_fields)
        self._validate_dataframe()

    def _get_statistic_plot_data_file(self):
        return join(self.statistics_plot_data_directory, self.daemon + self.statistics_filename_suffix)

    def _load_plot_data(self):
        statistic_plot_data = self._get_statistic_plot_data_file()
        with open(statistic_plot_data, 'r') as columns_file:
            full_data = json.load(columns_file)

        return full_data

    def plot(self):
        for element in self.plots_data.values():
            columns = element['columns']
            title = element['title']
            colors = self._color_palette(len(columns))

            _, ax = plt.subplots()
            for element, color in zip(columns, colors):
                self._basic_plot(ax, self.dataframe[element], label=element, color=color)

            self._save_custom_plot(ax, element, title)

class LogcollectorStatisticsVisualizer(DaemonStatisticsVisualizer):
    general_fields = ['Location', 'Target']

    def __init__(self, dataframes, store_path=gettempdir(), base_name=None):
        super().__init__(dataframes, 'logcollector', store_path)

    def _get_logcollector_location(self):
        """Get the list of unique logcollector targets (sockets) in the dataset."""
        return self.dataframe.Location.unique()

    def plot(self):
        for element in self.plots_data.values():
            fig, ax = plt.subplots()
            targets = self._get_logcollector_location()
            colors = self._color_palette(len(targets))
            for target, color in zip(targets, colors):
                self._basic_plot(ax, self.dataframe[self.dataframe.Location == target][element['columns']],
                                     label=target, color=color)

            self._save_custom_plot(ax, element['title'], element['title'])

class ClusterStatisticsVisualizer(DataVisualizer):
    expected_cluster_fields= ['node_name', 'activity', 'time_spent(s)']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()

    def _get_expected_fields(self) -> list:
        return self.expected_cluster_fields

    def plot(self):
        elements = list(self.dataframe['activity'].unique())

        for element in elements:
            _, ax = plt.subplots()
            nodes = self.dataframe[self.dataframe.activity == element]['node_name'].unique()
            current_df = self.dataframe[self.dataframe.activity == element]
            current_df.reset_index(drop=True, inplace=True)
            for node, color in zip(nodes, self._color_palette(len(nodes))):
                self._basic_plot(ax=ax, dataframe=current_df[current_df.node_name == node]['time_spent(s)'],
                                    label=node, color=color)
            self._save_custom_plot(ax, 'time_spent(s)', element.replace(' ', '_').lower(), cluster_log=True,
                                    statistics=DataVisualizer._get_statistics(
                                        current_df['time_spent(s)'], calculate_mean=True, calculate_median=True))


class IndexerAlerts(DataVisualizer):
    expected_fields = ['Total alerts']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()

    def _plot_agregated_alerts(self):
        _, ax = plt.subplots()
        df['Difference'] = df['Total alerts'].diff()


    def _plot_plain_alerts(self):
        _, ax = plt.subplots()
        self._basic_plot(ax=ax, dataframe=self.dataframe, label='alerts', self._color_palette(1))


    def plot(self):
        self._plot_plain_alerts()
        self._plot_agregated_alerts()


class IndexerVulnerabilities(DataVisualizer):
    expected_fields = ['Vulnerabilities']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()

    def plot(self):
        pass

