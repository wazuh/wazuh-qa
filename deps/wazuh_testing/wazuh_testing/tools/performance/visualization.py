from os.path import join
from re import sub
from sys import platform
from tempfile import gettempdir

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

BINARY_NON_PRINTABLE_HEADERS = ['PID', 'Daemon', 'Version']

ANALYSISD_CSV_HEADERS = {'cumulative': ['Timestamp', 'Total Events', 'Syscheck Events Decoded',
                                        'Syscollector Events Decoded', 'Rootcheck Events Decoded',
                                        'SCA Events Decoded', 'HostInfo Events Decoded',
                                        'WinEvt Events Decoded', 'Other Events Decoded',
                                        'Events processed (Rule matching)', 'Events received',
                                        'Events dropped', 'Alerts written', 'Firewall alerts written',
                                        'FTS alerts written'],
                         'non_cumulative': ['Timestamp', 'Syscheck queue', 'Syscollector queue',
                                            'Rootcheck queue', 'SCA queue', 'Hostinfo queue', 'Winevt queue',
                                            'Event queue', 'Rule matching queue', 'Alerts log queue',
                                            'Firewall log queue', 'Statistical log queue',
                                            'Archives log queue'],
                         'events': ['Timestamp', 'Syscheck EDPS', 'Syscollector EDPS', 'Rootcheck EDPS',
                                    'SCA EDPS', 'HostInfo EDPS', 'WinEvt EDPS', 'Other EDPS',
                                    'Events EDPS (Rule matching)'],
                         }
REMOTED_CSV_HEADERS = {}
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

    def _plot_binaries_dataset(self):
        elements = self.dataframe.columns.drop(BINARY_NON_PRINTABLE_HEADERS)
        for element in elements:
            fig, ax = plt.subplots()
            for daemon in self._get_daemons():
                ax.plot(self.dataframe[self.dataframe.Daemon == daemon][element], label=daemon)

            ax.legend(loc='center left', bbox_to_anchor=(1.0, 0.5))
            ax.set_ylabel(element)
            ax.set_title(f"{element} usage during the test")
            self._set_x_ticks_interval(ax)
            plt.xticks(rotation=90)
            csv_name = sub(pattern=r'\(.*\)', string=element, repl='')
            plt.savefig(join(self.store_path, f"{csv_name}.svg"), dpi=1200, format='svg')

    def plot(self):
        self._plot_binaries_dataset()

    def _get_daemons(self):
        """Get the list of Wazuh Daemons in the dataset"""
        return self.dataframe.Daemon.unique()
