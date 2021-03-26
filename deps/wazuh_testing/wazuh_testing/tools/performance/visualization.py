from os.path import join
from re import sub
from sys import platform
from tempfile import gettempdir

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

BINARY_NON_PRINTABLE_HEADERS = ['PID', 'Daemon', 'Version']

ANALYSISD_CSV_HEADERS = {
    'decoded_events': {'title': 'Events decoded per queue',
                       'columns': ['total_events_decoded', 'syscheck_events_decoded',
                                   'syscollector_events_decoded', 'rootcheck_events_decoded',
                                   'sca_events_decoded', 'hostinfo_events_decoded', 'winevt_events_decoded',
                                   'other_events_decoded', 'dbsync_messages_dispatched'],
                       },
    'queue_usage': { 'title': 'Queue usage during the test',
                     'columns': ['syscheck_queue_usage', 'syscollector_queue_usage', 'rootcheck_queue_usage',
                                 'sca_queue_usage', 'hostinfo_queue_usage', 'winevt_queue_usage',
                                 'dbsync_queue_usage', 'upgrade_queue_usage', 'event_queue_usage',
                                 'rule_matching_queue_usage', 'alerts_queue_usage', 'firewall_queue_usage',
                                 'statistical_queue_usage', 'archives_queue_usage'],
                     },
    'events_decoded_per_second': {'title': 'Events decoded per second',
                                  'columns': ['syscheck_edps', 'syscollector_edps', 'rootcheck_edps',
                                              'sca_edps', 'hostinfo_edps', 'winevt_edps',
                                              'other_events_edps', 'events_edps', 'dbsync_mdps'],
                                  },
    'alerts_info': {'title': 'Alerts and events info.',
                    'columns': ['events_processed', 'events_received', 'events_dropped', 'alerts_written',
                                'firewall_written', 'fts_written'],
                    }
}
REMOTED_CSV_HEADERS = {
    'events_info': {'title': 'Events sent and count',
                    'columns': ["evt_count", "ctrl_msg_count", "discarded_count", "msg_sent", 'dequeued_after_close']
                    },
    'queue_size': {'title': 'Queue status',
                   'columns': ['queue_size', 'total_queue_size']
                   },
    'tcp_sessions': {'title': 'TCP sessions',
                     'columns': ['tcp_sessions']},
    'recv_bytes': {'title': 'Bytes received',
                     'columns': ['recv_bytes']}
}
AGENTD_CSV_HEADERS = {}


class DataVisualizer:
    def __init__(self, dataframes, target, compare=False, store_path=gettempdir(), x_ticks_granularity='minutes',
                 x_ticks_interval=1):
        self.color_palette = None
        self.dataframes_path = dataframes
        self.dataframe = None
        self.compare = compare
        self.target = target
        self.store_path = store_path
        self._load_dataframes(self.dataframes_path)
        self._set_color_palette()
        self.x_ticks_granularity = x_ticks_granularity
        self.x_ticks_interval = x_ticks_interval
        sns.set(rc={'figure.figsize': (26, 9)})

    def _set_color_palette(self):
        """Sets the different colors to plot the dataframe"""
        size = self.dataframe.shape[1]
        self.color_palette = sns.hls_palette(size - 1, h=.5) if platform != 'sunos5' else None

    def _load_dataframes(self, dataframes_paths):
        for df_path in dataframes_paths:
            if self.dataframe is None:
                self.dataframe = pd.read_csv(df_path, index_col="Timestamp", parse_dates=True)
            else:
                new_csv = pd.read_csv(df_path, index_col="Timestamp", parse_dates=True)
                self.dataframe = pd.concat([self.dataframe, new_csv])

    def _set_x_ticks_interval(self, ax):
        if self.x_ticks_granularity == 'seconds':
            ax.xaxis.set_major_locator(mdates.SecondLocator(interval=self.x_ticks_interval))
        elif self.x_ticks_granularity == 'minutes':
            ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=self.x_ticks_interval))
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

    @staticmethod
    def _basic_plot(ax, dataframe, label=None):
        ax.plot(dataframe, label=label)

    def _save_custom_plot(self, ax, y_label, title, rotation=90):
        ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
        ax.set_ylabel(y_label)
        ax.set_title(title)
        self._set_x_ticks_interval(ax)
        plt.xticks(rotation=rotation)
        svg_name = sub(pattern=r'\(.*\)', string=y_label, repl='')
        plt.savefig(join(self.store_path, f"{svg_name}.svg"), dpi=1200, format='svg')

    def _plot_data(self, elements, binary_dataset, title=None, generic_label=None):
        if binary_dataset:
            for element in elements:
                fig, ax = plt.subplots()
                for daemon in self._get_daemons():
                    self._basic_plot(ax, self.dataframe[self.dataframe.Daemon == daemon][element], label=daemon)
                self._save_custom_plot(ax, element, f"{element} {title}")

        else:
            fig, ax = plt.subplots()
            for element in elements:
                self._basic_plot(ax, self.dataframe[element], label=element)
            self._save_custom_plot(ax, generic_label, title)

    def _plot_binaries_dataset(self):
        elements = self.dataframe.columns.drop(BINARY_NON_PRINTABLE_HEADERS)
        self._plot_data(elements, True, "usage during the test")

    def _plot_analysisd_dataset(self):
        for element in ANALYSISD_CSV_HEADERS:
            columns = ANALYSISD_CSV_HEADERS[element]['columns']
            title = ANALYSISD_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, binary_dataset=False, title=title, generic_label=element)

    def _plot_remoted_dataset(self):
        for element in REMOTED_CSV_HEADERS:
            columns = REMOTED_CSV_HEADERS[element]['columns']
            title = REMOTED_CSV_HEADERS[element]['title']
            self._plot_data(elements=columns, binary_dataset=False, title=title, generic_label=element)

    def _plot_agentd_dataset(self):
        pass

    def _plot_logcollector_dataset(self):
        pass

    def plot(self):
        self._plot_binaries_dataset()

    def _get_daemons(self):
        """Get the list of Wazuh Daemons in the dataset"""
        return self.dataframe.Daemon.unique()
