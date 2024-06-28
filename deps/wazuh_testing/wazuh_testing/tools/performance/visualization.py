import json
import logging
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

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
    """

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        """Initializes the DataVisualizer.

        Args:
            dataframes_paths (list): List of paths to CSV files.
            store_path (str, optional): Path to store the CSV images. Defaults to the temp directory.
            base_name (str, optional): Base name used to store the images.
        """
        self.dataframes_paths = dataframes_paths
        self.store_path = store_path
        self.base_name = base_name
        self.dataframe = pd.DataFrame()

        self._load_dataframes()
        sns.set_theme(rc={'figure.figsize': (26, 9)})

    @abstractmethod
    def _get_expected_fields(self):
        """Abstract method to define expected fields in the data.

        Returns:
            list: List of expected field names.
        """
        pass

    @abstractmethod
    def plot(self):
        """Abstract method to create data visualizations."""
        pass

    def _validate_dataframe(self) -> None:
        """Validates the loaded dataframe.

        Raises:
            ValueError: If there are missing mandatory fields or duplicated column names.
        """
        self._check_missing_mandatory_fields()
        self._check_no_duplicated()
        self._check_unexpected_values()

    def _check_no_duplicated(self):
        """Checks for duplicated column names in the dataframe.

        Raises:
            ValueError: If duplicate column names are found.
        """
        if self.dataframe.columns.duplicated().any():
            raise ValueError('Duplicate column names found in the CSV file.')

    def _check_missing_mandatory_fields(self):
        """Checks if mandatory fields are present in the dataframe.

        Raises:
            ValueError: If mandatory fields are missing.
        """
        if not (set(self._get_expected_fields()).issubset(set(self._get_data_columns()))):
            missing_fields = (set(self._get_expected_fields()) - set(self._get_data_columns()))
            raise ValueError(f"Missing some of the mandatory values: {missing_fields}")

    def _check_unexpected_values(self):
        """Checks for unexpected values in the dataframe.

        Raises:
            ValueError: If unexpected values are found.
        """
        if not (set(self._get_data_columns()).issubset(set(self._get_expected_fields()))):
            missing_fields = (set(self._get_data_columns()) - set(self._get_expected_fields()))
            logging.warning(f"Unexpected fields provided. These will not be plotted: {missing_fields}")

    def _get_data_columns(self) -> list:
        """Retrieves the list of column names from the loaded dataframe.

        Returns:
            list: List of column names.
        """
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
        """Calculate data statistics.

        Args:
            df (pandas.DataFrame): dataframe on which the operations will be applied.
            calculate_mean (bool, optional): specify whether or not the mean will be calculated.
            calculate_median (bool, optional): specify whether or not the median will be calculated.
        """
        statistics = ''

        if calculate_mean:
            statistics += f"Mean: {round(pd.Series.mean(df), 3)}\n"
        if calculate_median:
            statistics += f"Median: {round(pd.Series.median(df), 3)}\n"

        return statistics

    @staticmethod
    def _basic_plot(ax, dataframe, label=None, color=None):
        """Visualize simple dataframe.

        Args:
            ax (axes.SubplotBase): subplot base where the data will be printed.
            dataframe (pandas.Dataframe): dataframe containing the data from the CSVs.
            label (str, optional): optional label to add to the plot.
            color (tuple, optional): tuple defining the color (float, float).
        """
        ax.plot(dataframe, label=label, color=color)

    def _save_custom_plot(self, ax, y_label, title, rotation=90, disable_x_labels=False, statistics=None):
        """Add info to the plot, the legend and save the SVG image.

        Args:
            ax (axes.SubplotBase): subplot base where the data will be printed.
            y_label (str): label for the Y axis.
            title (str): title of the plot.
            rotation (int, optional): optional int to set the rotation of the X-axis labels.
            disable_x_labels (bool, optional): If True, the plot will not display the x-axis labels (timestamps).
            statistics (str, optional): optional statistics measures.
        """
        if statistics:
            ax.text(0.9, 0.9, statistics, fontsize=14, transform=plt.gcf().transFigure)

        ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
        ax.set_ylabel(y_label)
        ax.set_title(title)

        if not disable_x_labels:
            self._set_x_ticks_interval(ax)
            plt.xticks(rotation=rotation)
            svg_name = sub(pattern=r'\(.*\)', string=y_label, repl='')
        else:
            svg_name = sub(pattern=r'\(.*\)', string=title, repl='')

        if self.base_name is not None:
            svg_name = f"{self.base_name}_{svg_name}"

        plt.savefig(join(self.store_path, f"{svg_name}.svg"), dpi=1200, format='svg')


class BinaryDatavisualizer(DataVisualizer):
    """A class for visualizing binary metrics data.

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
        binary_metrics_fields_to_plot (list): List of binary metrics fields to plot.
        binary_metrics_extra_fields (list): List of additional binary metrics fields.
        binary_metrics_fields (list): Combined list of binary metrics fields.
    """
    binary_metrics_fields_to_plot = ["CPU", "VMS", "RSS", "USS",
                                     "PSS", "SWAP", "FD", "Read_Ops",
                                     "Write_Ops", "Disk_Read", "Disk_Written",
                                     "Disk_Read_Speed", "Disk_Write_Speed"]
    binary_metrics_extra_fields = ["Daemon", "Version", "PID"]
    binary_metrics_fields = binary_metrics_fields_to_plot + binary_metrics_extra_fields

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None, unify_child_daemon_metrics=False):
        """Initialize the BinaryDatavisualizer.

        Args:
            dataframes (list): List of dataframes containing binary metrics data.
            store_path (str, optional): Path to store visualizations. Defaults to system temp directory.
            base_name (str, optional): Base name for saved visualizations. Defaults to None.
            unify_child_daemon_metrics (bool, optional): Whether to unify child daemon metrics. Defaults to False.
        """
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()
        if unify_child_daemon_metrics:
            self.dataframe = self.dataframe.reset_index(drop=False)
            self._unify_dataframes()

    def _get_expected_fields(self):
        """Get the list of expected fields for binary metrics.

        Returns:
            list: List of expected binary metrics fields.
        """
        return self.binary_metrics_fields

    def _normalize_column_name(self, column_name: str):
        """Normalize column names by removing units within parentheses.

        Args:
            column_name (str): The column name to normalize.

        Returns:
            str: The normalized column name.
        """
        if '(' in column_name:
            return column_name.split('(')[0].strip()
        return column_name

    def _get_data_columns(self):
        """Get the list of data columns in the dataframe after normalization.

        Returns:
            list: List of normalized data column names.
        """
        column_names = self.dataframe.columns
        normalized_columns = [self._normalize_column_name(col) for col in column_names.tolist()]

        return normalized_columns

    def _get_daemons(self):
        """Get the list of unique Wazuh Daemons in the dataset.

        Returns:
            list: List of unique Daemon names.
        """
        return self.dataframe.Daemon.unique()

    def _get_fields_to_plot(self):
        """Get the list of fields to plot from the dataframe.

        Returns:
            list: List of fields to plot.
        """
        column_names = self.dataframe.columns
        fields_to_plot = []

        for field_to_plot in column_names:
            if self._normalize_column_name(field_to_plot) in self.binary_metrics_fields_to_plot:
                fields_to_plot.append(field_to_plot)

        return fields_to_plot

    def _unify_dataframes(self):
        """Unify the data of each process with their respective sub-processes."""
        pids = self.dataframe[['Daemon', 'PID']].drop_duplicates()
        versions = self.dataframe[['Daemon', 'Version']].drop_duplicates()

        daemons_list = [daemon_name for daemon_name in self._get_daemons() if "child" not in daemon_name]

        for daemon_name in daemons_list:
            self.dataframe.loc[self.dataframe['Daemon'].str.contains(daemon_name, na=False), 'Daemon'] = daemon_name

        columns_to_drop = ['Timestamp', 'Daemon', 'Version', 'PID']
        columns_to_sum = self.dataframe.columns.drop(columns_to_drop)

        self.dataframe = self.dataframe.groupby(['Timestamp', 'Daemon'])[columns_to_sum].sum().reset_index(drop=False)

        self.dataframe = self.dataframe.merge(pids[['Daemon', 'PID']], on='Daemon', how='left')
        self.dataframe = self.dataframe.merge(versions[['Daemon', 'Version']], on='Daemon', how='left')

    def plot(self):
        """Plot the binary metrics data for each field to be plotted.

        This method creates and saves plots for each binary metric field.
        """
        columns_to_plot = self._get_fields_to_plot()
        for element in columns_to_plot:
            _, ax = plt.subplots()
            daemons = self._get_daemons()
            colors = self._color_palette(len(daemons))
            for daemon, color in zip(daemons, colors):
                self._basic_plot(ax, self.dataframe[self.dataframe.Daemon == daemon][element],
                                 label=daemon, color=color)

            self._save_custom_plot(ax, element, element)


class DaemonStatisticsVisualizer(DataVisualizer):
    """A class for visualizing daemon statistics data.

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
        daemon (str): Name of the daemon for which statistics are visualized.
        plots_data (dict): Data required for plotting statistics.
        expected_fields (list): List of expected fields for the daemon statistics.
    """

    general_fields = ['API Timestamp', 'Interval (Timestamp-Uptime)']
    statistics_plot_data_directory = join(dirname(realpath(__file__)), '..', '..', 'data', 'data_visualizer')
    statistics_filename_suffix = '_csv_headers.json'

    def __init__(self, dataframes_paths, daemon, store_path=gettempdir(), base_name=None):
        """Initialize the DaemonStatisticsVisualizer.

        Args:
            dataframes (list): List of dataframes containing daemon statistics data.
            daemon (str): Name of the daemon for which statistics are visualized.
            store_path (str, optional): Path to store visualizations. Defaults to system temp directory.
            base_name (str, optional): Base name for saved visualizations. Defaults to None.
        """
        self.daemon = daemon
        super().__init__(dataframes_paths, store_path, base_name)
        self.plots_data = self._load_plot_data()
        self.expected_fields = []
        for graph in self.plots_data.values():
            for column in graph['columns']:
                self.expected_fields.append(column)
        self.expected_fields.extend(self.general_fields)
        self._validate_dataframe()

    def _get_expected_fields(self):
        """Get the list of expected fields for the daemon statistics.

        Returns:
            list: List of expected fields.
        """
        return self.expected_fields

    def _get_statistic_plot_data_file(self):
        """Get the file path for the statistics plot data file.

        Returns:
            str: Path to the statistics plot data file.
        """
        return join(self.statistics_plot_data_directory, self.daemon + self.statistics_filename_suffix)

    def _load_plot_data(self):
        """Load the plot data from the statistics plot data file.

        Returns:
            dict: Data required for plotting statistics.
        """
        statistic_plot_data = self._get_statistic_plot_data_file()
        with open(statistic_plot_data) as columns_file:
            full_data = json.load(columns_file)

        return full_data

    def plot(self):
        """Plot the daemon statistics data for each field to be plotted.

        This method creates and saves plots for each statistic field.
        """
        for element in self.plots_data.values():
            columns = element['columns']
            title = element['title']
            colors = self._color_palette(len(columns))

            _, ax = plt.subplots()
            for column, color in zip(columns, colors):
                self._basic_plot(ax, self.dataframe[column], label=column, color=color)
            self._save_custom_plot(ax, title, title)


class LogcollectorStatisticsVisualizer(DaemonStatisticsVisualizer):
    """A class for visualizing logcollector statistics data.

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
        general_fields (list): List of general fields for logcollector statistics.
    """
    general_fields = ['Location', 'Target']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        """Initialize the LogcollectorStatisticsVisualizer.

        Args:
            dataframes (list): List of dataframes containing logcollector statistics data.
            store_path (str, optional): Path to store visualizations. Defaults to system temp directory.
            base_name (str, optional): Base name for saved visualizations. Defaults to None.
        """
        super().__init__(dataframes_paths, 'logcollector', store_path, base_name)

    def _get_expected_fields(self):
        """Get the list of expected fields for logcollector statistics.

        Returns:
            list: List of expected fields.
        """
        return self.general_fields

    def _get_logcollector_location(self):
        """Get the list of unique logcollector targets (sockets) in the dataset.

        Returns:
            numpy.ndarray: Array of unique logcollector targets.
        """
        return self.dataframe.Location.unique()

    def plot(self):
        """Plot the logcollector statistics data for each target.

        This method creates and saves plots for each logcollector target.
        """
        for element in self.plots_data.values():
            _, ax = plt.subplots()
            targets = self._get_logcollector_location()
            colors = self._color_palette(len(targets))
            for target, color in zip(targets, colors):
                self._basic_plot(ax, self.dataframe[self.dataframe.Location == target][element['columns']],
                                 label=target, color=color)

            self._save_custom_plot(ax, element['title'], element['title'])


class ClusterStatisticsVisualizer(DataVisualizer):
    """A class for visualizing cluster statistics data.

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        base_name (str, optional): base name used to store the images.
        expected_cluster_fields (list): List of expected fields for cluster statistics.
    """
    expected_cluster_fields = ['node_name', 'activity', 'time_spent(s)']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        """Initialize the ClusterStatisticsVisualizer.

        Args:
            dataframes_paths (list): List of paths to dataframes containing cluster statistics data.
            store_path (str, optional): Path to store visualizations. Defaults to system temp directory.
            base_name (str, optional): Base name for saved visualizations. Defaults to None.
        """
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()

    def _get_expected_fields(self) -> list:
        """Get the list of expected fields for cluster statistics.

        Returns:
            list: List of expected cluster fields.
        """
        return self.expected_cluster_fields

    def plot(self):
        """Plot the cluster statistics data for each activity.

        This method creates and saves plots for each cluster activity.
        """
        elements = list(self.dataframe['activity'].unique())

        for element in elements:
            _, ax = plt.subplots()
            nodes = self.dataframe[self.dataframe.activity == element]['node_name'].unique()
            current_df = self.dataframe[self.dataframe.activity == element]
            current_df.reset_index(drop=True, inplace=True)
            for node, color in zip(nodes, self._color_palette(len(nodes))):
                self._basic_plot(ax=ax, dataframe=current_df[current_df.node_name == node]['time_spent(s)'],
                                 label=node, color=color)
            self._save_custom_plot(ax, 'time_spent(s)', element.replace(' ', '_').lower(), disable_x_labels=True,
                                   statistics=DataVisualizer._get_statistics(
                                        current_df['time_spent(s)'], calculate_mean=True, calculate_median=True))


class IndexerAlerts(DataVisualizer):
    """A class for visualizing indexer alerts data.

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        expected_fields (list): List of expected fields for indexer alerts.
    """
    expected_fields = ['Total alerts']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        """Initialize the IndexerAlerts visualizer.

        Args:
            dataframes_paths (list): List of paths to dataframes containing indexer alerts data.
            store_path (str, optional): Path to store visualizations. Defaults to system temp directory.
            base_name (str, optional): Base name for saved visualizations. Defaults to None.
        """
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()

    def _get_expected_fields(self):
        """Get the list of expected fields for indexer alerts.

        Returns:
            list: List of expected fields.
        """
        return self.expected_fields

    def _calculate_timestamp_interval(self):
        """Calculate the interval between timestamps in seconds.

        Returns:
            float: Interval between timestamps in seconds.
        """
        interval = self.dataframe.index[1] - self.dataframe.index[0]
        return interval.total_seconds()

    def _plot_agregated_alerts(self):
        """Plot the aggregated alerts per timestamp.

        This method creates and saves a plot for the aggregated alerts.
        """
        _, ax = plt.subplots()
        self.dataframe['Difference'] = self.dataframe['Total alerts'].diff()
        self.dataframe['Difference'] = self.dataframe['Difference'] / self._calculate_timestamp_interval()

        self._basic_plot(ax=ax, dataframe=self.dataframe['Difference'], label='Alerts per timestamp',
                         color=self._color_palette(1)[0])
        self._save_custom_plot(ax, 'Different alerts', 'Difference alerts')

    def _plot_plain_alerts(self):
        """Plot the total alerts.

        This method creates and saves a plot for the total alerts.
        """
        _, ax = plt.subplots()
        self._basic_plot(ax=ax, dataframe=self.dataframe['Total alerts'], label='Total alerts',
                         color=self._color_palette(1)[0])
        self._save_custom_plot(ax, 'Total alerts', 'Total alerts')

    def plot(self):
        """Plot the indexer alerts data.

        This method creates and saves plots for both total alerts and aggregated alerts.
        """
        self._plot_plain_alerts()
        self._plot_agregated_alerts()


class IndexerVulnerabilities(DataVisualizer):
    """A class for visualizing indexer vulnerabilities data.

    Attributes:
        dataframes_paths (list): paths of the CSVs.
        dataframe (pandas.Dataframe): dataframe containing the info from all the CSVs.
        store_path (str): path to store the CSV images. Defaults to the temp directory.
        expected_fields (list): List of expected fields for indexer vulnerabilities.
    """
    expected_fields = ['Total vulnerabilities']

    def __init__(self, dataframes_paths, store_path=gettempdir(), base_name=None):
        """Initialize the IndexerVulnerabilities visualizer.

        Args:
            dataframes_paths (list): List of paths to dataframes containing indexer vulnerabilities data.
            store_path (str, optional): Path to store visualizations. Defaults to system temp directory.
            base_name (str, optional): Base name for saved visualizations. Defaults to None.
        """
        super().__init__(dataframes_paths, store_path, base_name)
        self._validate_dataframe()

    def _get_expected_fields(self):
        """Get the list of expected fields for indexer vulnerabilities.

        Returns:
            list: List of expected fields.
        """
        return self.expected_fields

    def plot(self):
        """Plot the indexer vulnerabilities data.

        This method creates and saves a plot for the total vulnerabilities.
        """
        _, ax = plt.subplots()
        self._basic_plot(ax=ax, dataframe=self.dataframe['Total vulnerabilities'], label='Indexed Vulnerabilities',
                         color=self._color_palette(1)[0])
        self._save_custom_plot(ax, 'Total Vulnerabilities', 'Total vulnerabilities')
