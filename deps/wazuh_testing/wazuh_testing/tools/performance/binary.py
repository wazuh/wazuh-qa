# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import csv
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from os import makedirs
from os.path import join, isfile
from re import compile
from sys import platform
from tempfile import gettempdir
from threading import Thread, Event
from time import sleep

import psutil

MONITOR_LIST = []

logger = logging.getLogger('wazuh-monitor')
logger.setLevel(logging.INFO)


class Monitor:
    """Class to monitor a binary process and extract data referring to the CPU usage, memory consumption, etc.

    Args:
        process_name (str): name of the process to monitor.
        value_unit (str, optional): unit to store the bytes values. Defaults to KB.
        time_step (int, optional): time between each scan in seconds. Defaults to 1 second.
        version (str, optional): version of the binary. Defaults to None.
        dst_dir (str, optional): directory to store the CSVs. Defaults to temp directory.

    Attributes:
        process_name (str): name of the process to monitor.
        value_unit (str): unit to store the bytes values. Defaults to KB.
        time_step (int): time between each scan in seconds. Defaults to 1 second.
        version (str): version of the binary. Defaults to None.
        dst_dir (str): directory to store the CSVs. Defaults to temp directory.
        pid (int): PID of the process.
        event (thread.Event): thread Event used to control the scans.
        thread (thread): thread to scan the data.
        csv_file (str): path to the CSV file.
    """
    def __init__(self, process_name, value_unit='KB', time_step=1, version=None, dst_dir=gettempdir()):
        self.process_name = process_name
        self.value_unit = value_unit
        self.time_step = time_step
        self.version = version
        self.data_units = {'B': 0, 'KB': 1, 'MB': 2}
        self.platform = platform
        self.dst_dir = dst_dir
        self.pid = None
        self.event = None
        self.thread = None
        self.set_pid(self.process_name)
        self.csv_file = join(self.dst_dir, f'{self.process_name}.csv')

    def set_pid(self, process_name):
        """Search and set the PID of the process.

        Raises:
            ValueError: if the process is not running.
        """
        for proc in psutil.process_iter():
            # These two binaries are executed using the Python interpreter instead of
            # directly execute them as daemons. That's why we need to search the .py file in
            # the cmdline instead of searching it in the name
            if process_name in ['wazuh-clusterd', 'wazuh-apid']:
                if any(filter(lambda x: f"{process_name}.py" in x, proc.cmdline())):
                    self.pid = proc.pid
            elif process_name in proc.name():
                self.pid = proc.pid

        if self.pid is None:
            raise ValueError(f"The process {process_name} is not running.")

    def get_process_info(self, proc):
        """Collect the data from the process.

        The monitor collects this info from the process:
            - Daemon: daemon name.
            - Version: version.
            - Timestamp: timestamp of the scan.
            - PID: pid of the process.
            - CPU(%): cpu percent of the process. It maybe greater than 100% if the process uses multiple threads.
            - VMS: Virtual Memory Size.
            - RSS: Resident Set Size.
            - USS: Unique Set Size.
            - PSS: Proportional Set Size.
            - SWAP: memory of the process in the swap space.
            - FD: file descriptors opened by the process.
            - Read_Ops: read operations.
            - Write_Ops: write operations.
            - Disk_Read: Bytes read by the process.
            - Disk_Written: Bytes written by the process.
            - Disk(%): percentage of the I/O operations ran by the process compared with the OS.

        Args:
            proc (psutil.proc): psutil object with the data of the process.

        Returns:
            dict: Dictionary containing the data of the process.
        """
        def unit_conversion(x):
            return x / (1024 ** self.data_units[self.value_unit])

        # Pre-initialize the info dictionary. If there's a problem while taking metrics of the binary (i.e. it crashed)
        # the CSV will set all its values to 0 to easily identify if there was a problem or not
        info = {'Daemon': self.process_name, 'Version': self.version, 'Timestamp': datetime.now().strftime('%H:%M:%S'),
                'PID': self.pid, 'CPU(%)': 0.0, f'VMS({self.value_unit})': 0.0, f'RSS({self.value_unit})': 0.0,
                f'USS({self.value_unit})': 0.0, f'PSS({self.value_unit})': 0.0,
                f'SWAP({self.value_unit})': 0.0, 'FD': 0.0, 'Read_Ops': 0.0, 'Write_Ops': 0.0,
                f'Disk_Read({self.value_unit})': 0.0, f'Disk_Written({self.value_unit})': 0.0, 'Disk(%)': 0.0,
                }

        try:
            with proc.oneshot():
                info['CPU(%)'] = proc.cpu_percent(interval=None)
                memory_data = proc.memory_full_info()
                info[f'VMS({self.value_unit})'] = unit_conversion(memory_data.vms)
                info[f'RSS({self.value_unit})'] = unit_conversion(memory_data.rss)
                info[f'USS({self.value_unit})'] = unit_conversion(memory_data.uss)
                info[f'PSS({self.value_unit})'] = unit_conversion(memory_data.pss)
                info[f'SWAP({self.value_unit})'] = unit_conversion(memory_data.swap)
                info['FD'] = proc.num_fds()

                if self.platform == 'linux' or platform == "win32":
                    io_counters = proc.io_counters()
                    disk_usage_process = io_counters.read_bytes + io_counters.write_bytes
                    disk_io_counter = psutil.disk_io_counters()
                    disk_total = disk_io_counter.read_bytes + disk_io_counter.write_bytes
                    info['Read_Ops'] = io_counters.read_count
                    info['Write_Ops'] = io_counters.write_count
                    info[f'Disk_Read({self.value_unit})'] = unit_conversion(io_counters.read_bytes)
                    info[f'Disk_Written({self.value_unit})'] = unit_conversion(io_counters.write_bytes)
                    info['Disk(%)'] = disk_usage_process / disk_total * 100
        finally:
            info.update({key: round(value, 2) for key, value in info.items() if isinstance(value, (int, float))})
            logger.debug(f'Recollected data for process {proc.pid}')
            return info

    def _write_csv(self, data):
        """Write the collected data in a CSV file.

        Args:
            data (dict): dictionary containing the data collected from the process.
        """
        header = not isfile(self.csv_file)
        with open(self.csv_file, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            if header:
                csv_writer.writerow(list(data))

            csv_writer.writerow(list(data.values()))
        logger.debug(f'Added new entry in {self.csv_file}')

    def _monitor_process(self):
        """Private function that runs the function to extract data."""
        proc = psutil.Process(self.pid)
        while not self.event.is_set():
            data = dict()
            try:
                data = self.get_process_info(proc)
            except Exception as e:
                logger.error(f'Exception with {self.process_name} | {e}')
                print(e.with_traceback())
            finally:
                self._write_csv(data)
            sleep(self.time_step)

    def run(self):
        """Run the event and thread monitoring functions."""
        self.event = Event()
        self.thread = Thread(target=self._monitor_process)
        self.thread.start()

    def start(self):
        """Start the monitoring threads."""
        self.run()
        logger.info(f'Started monitoring process {self.process_name} ({self.pid})')

    def shutdown(self):
        """Stop all the monitoring threads."""
        self.event.set()
        self.thread.join()


class LogParser(ABC):
    """Class to parse a log file and extract specified data based on a regular expression.

    Args:
        log_file (str): log file path.
        regex (regex): regular expression to be applied to the log file content.
        columns (list, str): csv headers.
        dst_dir (str, optional): directory to store the CSVs. Defaults to temp directory.

    Attributes:
        log_file (str): log file path.
        regex (regex): regular expression to be applied to the log file content.
        columns (list, str): csv headers.
        dst_dir (str): directory to store the CSVs. Defaults to temp directory.
        data (dict): processed log file.
    """

    def __init__(self, log_file, regex, columns, dst_dir=gettempdir()):
        self.log_file = log_file
        self.dst_dir = dst_dir
        self.regex = compile(regex)
        self.columns = columns
        self.data = None
        super().__init__()

    @abstractmethod
    def _log_parser(self):
        """Function to be overloaded by specifying in each child function the necessary logic to parse the log file."""
        pass

    def write_csv(self):
        """Function in charge of saving the CSV files according to their label."""
        try:
            makedirs(self.dst_dir)
        except OSError:
            pass

        for key, value in self.data.items():
            with open(join(self.dst_dir, f"{key.replace(' ', '_')}.csv".lower()), 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(self.columns)
                writer.writerows(value)


class ClusterLogParser(LogParser):
    """Logparser child class, this is exclusively in charge of parsing the cluster logs.

    Args:
        log_file (str): log file path.
        dst_dir (str, optional): directory to store the CSVs. Defaults to temp directory.

    Attributes:
        log_file (str): log file path.
        dst_dir (str): directory to store the CSVs. Defaults to temp directory.
        data (dict): processed log file.
    """
    def __init__(self, log_file, dst_dir=gettempdir()):
        # group1 Timestamp - group2 node_name - group3 activity - group4 time_spent(s)
        regex = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) .* ' \
                r'\[Worker .*_(manager_\d+)] \[(.*)] Finished in (\d+.\d+)s.*'
        columns = ['Timestamp', 'node_name', 'activity', 'time_spent(s)']
        super().__init__(log_file, regex, columns, dst_dir)

    def _log_parser(self):
        """Function in charge of parsing the information of the cluster.log file."""
        performance_information = dict()
        with open(self.log_file) as log:
            for match in self.regex.finditer(log.read()):
                try:
                    performance_information[match.group(3)].append(match.groups())
                except KeyError:
                    performance_information[match.group(3)] = list()
                    performance_information[match.group(3)].append(match.groups())

        return performance_information

    def write_csv(self):
        self.data = self._log_parser()
        super().write_csv()
