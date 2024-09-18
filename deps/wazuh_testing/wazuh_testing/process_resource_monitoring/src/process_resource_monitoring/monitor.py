# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Process resource usage monitor module.

This module provides the class `Monitor` to monitor the usage of different
process resources over time. It allows to select the sampling frequency
apart from the units in which to display the data.

List of metrics collected:
 - Daemon
 - Version
 - Timestamp
 - PID
 - CPU(%)
 - VMS
 - RSS
 - USS
 - PSS
 - SWAP
 - FD
 - Read_Ops
 - Write_Ops
 - Disk_Read
 - Disk_Written
"""

import csv
from datetime import datetime
from os.path import isfile, join
from sys import platform
from tempfile import gettempdir
from threading import Event, Thread
from time import sleep
from typing import Any, Dict, List, Literal, Optional

import psutil

from process_resource_monitoring._logger import logger


class Monitor:
    """Process resource usage monitoring class.

    Class to monitor a binary process and extract data referring to the
    CPU usage, memory consumption, etc. Full list can be found in the
    method `get_process_info` docstring.

    Instance methods:
        __init__:
            Creates a thread to monitor a process.
        get_process_info:
            Collect the data from the process.
        start:
            Start the monitoring threads.
        shutdown:
            Stop all the monitoring threads.

    Class methods:
        get_process_pids:
            Obtain the PIDs of the process and its children's if there
            are any.
    """

    _DATA_UNITS: Dict[str, int] = {'B': 0, 'KB': 1, 'MB': 2}

    def __init__(
        self,
        process_name: str,
        pid: int,
        value_unit: Literal['B', 'KB', 'MB'] = 'KB',
        time_step: int = 1,
        version: Optional[str] = None,
        dst_dir: str = gettempdir(),
    ) -> None:
        """Create a thread for monitoring one process.

        Args:
            process_name (str): name of the process to monitor.
            pid (int): PID of the process.
            value_unit (str, optional): unit to store the bytes values. Defaults to KB.
            time_step (int, optional): time in seconds between each scan. Defaults to 1.
            version (str, optional): version of the binary. Defaults to None.
            dst_dir (str, optional): directory to store the CSVs. Defaults to /tmp directory.
        """
        self._process_name: str = process_name
        self._pid: int = pid
        self._value_unit: str = value_unit
        self._time_step: int = time_step
        self._version: Optional[str] = version
        self._platform: str = platform
        self._dst_dir: str = dst_dir
        self._proc: Optional[psutil.Process] = None
        self._event: Optional[Event] = None
        self._thread: Optional[Thread] = None
        self._previous_read: Optional[str] = None
        self._previous_write: Optional[str] = None
        self._csv_file: str = join(self._dst_dir, f"{self._process_name.replace('.py', '')}.csv")
        self.set_process()

    @classmethod
    def get_process_pids(cls, process_name: str, check_children: bool = True) -> List[int]:
        """Obtain the PIDs of the process and its children's if there are any.

        Args:
            process_name (str): name of the process.
            check_children (bool, optional): Check for children PIDs.
                Defaults to True.

        Returns:
            (List[int]): List of integers with the PIDs.

        Raises:
            ValueError: if the process is not running
        """
        for proc in psutil.process_iter():
            if any(filter(lambda x: f'{process_name}' in x, proc.cmdline())):
                pid = proc.pid
                break
        else:
            raise ValueError(f'The process {process_name} is not running')

        if not check_children:
            return [pid]

        # Look for all the children PIDs
        parent_pid = psutil.Process(pid).parent().pid
        if parent_pid == 1:
            parent_pid = pid

        return [parent_pid] + [child.pid for child in psutil.Process(parent_pid).children(recursive=True)]

    def get_process_info(self, proc: psutil.Process) -> Dict[str, Any]:
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

        Args:
            proc (psutil.Process): psutil object with the data of the process.

        Returns:
            (Dict[str, Any]): Dictionary containing the data of the process.
        """

        def unit_conversion(number: int) -> float:
            """Converts bytes to the specified unit in the constructor.

            Args:
                number (int): number in bytes to be converted.

            Returns:
                (float): number of the unit chosen in the constructor.
            """
            return number / (1024 ** self._DATA_UNITS[self._value_unit])

        # Pre-initialize the info dictionary. If there's a problem while taking metrics of the binary (i.e. it crashed)
        # the CSV will set all its values to 0 to easily identify if there was a problem or not
        info = {
            'Daemon': self._process_name,
            'Version': self._version,
            'Timestamp': datetime.now().strftime('%Y/%m/%d %H:%M:%S'),
            'PID': self._pid,
            'CPU(%)': 0.0,
            f'VMS({self._value_unit})': 0.0,
            f'RSS({self._value_unit})': 0.0,
            f'USS({self._value_unit})': 0.0,
            f'PSS({self._value_unit})': 0.0,
            f'SWAP({self._value_unit})': 0.0,
            'FD': 0.0,
            'Read_Ops': 0.0,
            'Write_Ops': 0.0,
            f'Disk_Read({self._value_unit})': 0.0,
            f'Disk_Written({self._value_unit})': 0.0,
            f'Disk_Read_Speed({self._value_unit}/s)': 0.0,
            f'Disk_Write_Speed({self._value_unit}/s)': 0.0,
        }

        try:
            with proc.oneshot():
                info['CPU(%)'] = proc.cpu_percent(interval=None)
                memory_data = proc.memory_full_info()
                info[f'VMS({self._value_unit})'] = unit_conversion(memory_data.vms)
                info[f'RSS({self._value_unit})'] = unit_conversion(memory_data.rss)
                info[f'USS({self._value_unit})'] = unit_conversion(memory_data.uss)
                info[f'PSS({self._value_unit})'] = unit_conversion(memory_data.pss)
                info[f'SWAP({self._value_unit})'] = unit_conversion(memory_data.swap)
                info['FD'] = proc.num_fds()

                if self._platform == 'linux' or platform == 'win32':
                    io_counters = proc.io_counters()
                    info['Read_Ops'] = io_counters.read_count
                    info['Write_Ops'] = io_counters.write_count
                    info[f'Disk_Read({self._value_unit})'] = unit_conversion(io_counters.read_bytes)
                    info[f'Disk_Written({self._value_unit})'] = unit_conversion(io_counters.write_bytes)
                    if self._previous_read is not None and self._previous_write is not None:
                        read_speed = (info[f'Disk_Read({self._value_unit})'] - self._previous_read) / self._time_step
                        write_speed = (info[f'Disk_Written({self._value_unit})'] - self._previous_write) \
                            / self._time_step
                        info[f'Disk_Read_Speed({self._value_unit}/s)'] = read_speed
                        info[f'Disk_Write_Speed({self._value_unit}/s)'] = write_speed
                        self._previous_read = info[f'Disk_Read({self._value_unit})']
                        self._previous_write = info[f'Disk_Written({self._value_unit})']
                    else:
                        self._previous_read = info[f'Disk_Read({self._value_unit})']
                        self._previous_write = info[f'Disk_Written({self._value_unit})']
        except psutil.NoSuchProcess:
            logger.warning(f'Lost PID for {self._process_name}')
            self.shutdown()
        finally:
            info.update({key: round(value, 2) for key, value in info.items() if isinstance(value, (int, float))})
            logger.debug(f'Recollected data for process {self._pid}')

        return info

    def is_event_set(self) -> bool:
        """Check if the internal flag for the Monitor event is set."""
        return self._event.is_set()

    def set_process(self) -> None:
        """Create psutil.Process instance (map system process to be accessible in Python) and save it.

        Raises:
            ValueError: if the system process is not running.
        """
        try:
            self._proc = psutil.Process(self._pid)
        except psutil.NoSuchProcess as err:
            raise ValueError(f'The process {self._process_name} is not running.') from err

    def start(self) -> None:
        """Start the monitoring threads."""
        self._event = Event()
        self._thread = Thread(target=self._monitor_process)
        self._thread.start()
        logger.info(f'Started monitoring process {self._process_name} ({self._pid})')

    def shutdown(self) -> None:
        """Stop all the monitoring threads."""
        self._event.set()
        self._thread.join()

    def _write_csv(self, data: Dict[str, Any]) -> None:
        """Write the collected data in a CSV file.

        Args:
            data (Dict[str, Any]): dictionary containing the data collected from
                the process.
        """
        header = not isfile(self._csv_file)
        with open(self._csv_file, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            if header:
                csv_writer.writerow(list(data))

            csv_writer.writerow(list(data.values()))
        logger.debug(f'Added new entry in {self._csv_file}')

    def _monitor_process(self) -> None:
        """Private function that runs the function to extract data."""
        while not self.is_event_set():
            data = dict()
            try:
                data = self.get_process_info(self._proc)
            except Exception as e:
                logger.error(f'Exception with {self._process_name} | {e}')
            finally:
                self._write_csv(data)
            sleep(self._time_step)
