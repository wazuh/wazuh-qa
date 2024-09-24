# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Disk and partition usage tracking module.

The main purpose is to track the space usage of different files and
folders of a Wazuh installation. It is capable of tracking the disk
usage of one or multiple files/directories, showing the space it takes
relative to the partition in which it is located.
"""


import csv
import os
from datetime import datetime
from tempfile import gettempdir
from threading import Event, Thread
from time import sleep
from typing import Any, Dict, Optional

import psutil

from process_resource_monitoring._logger import logger


class DiskUsageTracker:
    """Class to track disk usage of the Wazuh installation components over time.

    Instance methods:
        __init__:
            Creates a thread to track the usage of a file/directory.
        get_file_info:
            Collect the data from the file.
        get_file_size:
            Get size of the file in the selected unit.
        get_disk_usage:
            Get the disk usage of the file in the partition it is located.
        is_event_set:
            Check if the thread has the event set (unhealthy if it has).
        start:
            Start the monitoring thread.
        shutdown:
            Stop the monitoring thread.
    """

    _DATA_UNITS: Dict[str, int] = {'B': 0, 'KB': 1, 'MB': 2, 'GB': 3, 'TB': 4}

    def __init__(self, file_path: str, value_unit: str = 'GB', time_step: int = 1, dst_dir: str = gettempdir()) -> None:
        """Initialize the tracker to monitor space usage .

        Args:
            file_path (str): path of the file/dir.
            value_unit (str, optional): unit to store the bytes values. Defaults to GB.
            time_step (int, optional): time in seconds between each scan. Defaults to 1.
            dst_dir (str, optional): directory to store the CSVs. Defaults to /tmp directory.
        """
        self._file_path: str = file_path
        self._file_name: str = os.path.basename(self._file_path)
        self._value_unit: str = value_unit
        self._time_step: int = time_step
        self._event: Optional[Event] = None
        self._thread: Optional[Thread] = None
        self._dst_dir: str = dst_dir
        self._csv_file: str = os.path.join(self._dst_dir, f"{self._file_name.replace('.', '_')}.csv")
        self._partition: Optional[str] = self._get_partition_for_path(self._file_path)

    def get_file_info(self) -> Dict[str, Any]:
        """Collect the data from the file/directory.

        This information is the following:
            - File: name of the file.
            - Timestamp: timestamp of the scan.
            - Path: full path of the file.
            - Size: size in selected units of the file.
            - Usage: percentage of the space the file takes relative to the partition's size.
            - Mod_time: last time the file was modified.
            - Acc_time: last time the file was accessed.
            - Creat_time: time of the creation (Windows) or metadata change time (Unix).

        Returns:
            data (Dict[str, Any]): dictionary containing the data collected from the file.
        """

        def convert_time(t: float) -> str:
            """Convert time in milliseconds since the epoch to %d/%m/%Y-%H:%M:%S.%f.

            Args:
                t (float): time in milliseconds since the epoch.

            Returns:
                (str): formatted time.
            """
            return datetime.fromtimestamp(t).strftime('%d/%m/%Y-%H:%M:%S.%f')

        # Pre-initialize the info dictionary. If there's a problem while taking metrics of the file (i.e. it crashed)
        # the CSV will set all its values to 0 to easily identify if there was a problem or not
        info = {
            'File': self._file_name,
            'Timestamp': datetime.now().strftime('%Y/%m/%d %H:%M:%S'),
            'Path': self._file_path,
            f'Size({self._value_unit})': 0.0,
            'Usage(%)': 0.0,
            'Mod_time': datetime.min,
            'Acc_time': datetime.min,
            'Creat_time': datetime.min
        }

        try:
            info[f'Size({self._value_unit})'] = self.get_file_size(self._file_path)
            info['Usage(%)'] = self.get_disk_usage(self._file_path, self._partition)
            info['Mod_time'] = convert_time(os.path.getmtime(self._file_path))
            info['Acc_time'] = convert_time(os.path.getatime(self._file_path))
            info['Creat_time'] = convert_time(os.path.getctime(self._file_path))
        except ValueError:
            logger.warning(f'File {self._file_path} is not accessible.')
            if self._event is not None:
                self.shutdown()
        finally:
            info.update({key: round(value, 2) for key, value in info.items() if isinstance(value, (int, float))})
            logger.debug(f'Recollected data for file {self._file_path}')

        return info

    def get_file_size(self, path: str) -> float:
        """Get the size of the specified file.

        Args:
            path (str): Path of the file.

        Returns:
            (float): Size of the file in the unit specified in the constructor.

        Raises:
            ValueError: if there is no file nor directory with that path.
        """
        if os.path.isfile(path):
            size_bytes = os.path.getsize(path)

            return self._unit_conversion(size_bytes)
        elif os.path.isdir(path):
            # Directory, calculate its size recursively
            total_size = 0
            for dirpath, _dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        size_bytes = os.path.getsize(fp)
                        total_size += self._unit_conversion(size_bytes)
            return total_size
        else:
            raise ValueError(f'{path} is neither a file nor a directory.')

    def get_disk_usage(self, path: str, partition: Optional[str]) -> float:
        """Get the disk usage of the file/directory in its partition.

        Returns:
            (float): percentage of the partition size used by the file/dir.
        """
        if partition is None:
            return -1.0

        partition_size_bytes = psutil.disk_usage(partition).total
        partition_size = self._unit_conversion(partition_size_bytes)

        return self.get_file_size(path) / partition_size

    def is_event_set(self) -> bool:
        """Check if the internal flag for the tracker event is set.

        Returns:
            (bool): True if the internal flag is set, False otherwise.
        """
        return self._event.is_set()

    def start(self) -> None:
        """Start the monitoring threads."""
        self._event = Event()
        self._thread = Thread(target=self._monitor_file)
        self._thread.start()
        logger.info(f'Started monitoring file {self._file_name} ({self._file_path})')

    def shutdown(self) -> None:
        """Stop all the monitoring threads."""
        self._event.set()
        self._thread.join()

    def _get_partition_for_path(self, path: str) -> str:
        """Get the *physical* partition that contains a file given its path.

        Args:
            path (str): path of the file to get its partition.

        Returns:
            (str): Mount point of the partition containing the file. None if the file does not exist.
        """
        if os.path.exists(path):
            for partition in psutil.disk_partitions():
                if path.startswith(partition.mountpoint):
                    return partition.mountpoint
        return None

    def _monitor_file(self) -> None:
        """Private function that runs the function to extract data."""
        while not self._event.is_set():
            data = dict()
            try:
                data = self.get_file_info()
            except Exception as e:
                logger.error(f'Exception with {self._file_name} | {e}')
            finally:
                self._write_csv(data)
            sleep(self._time_step)

    def _unit_conversion(self, number: int) -> float:
        """Converts bytes to the specified unit in the constructor.

        Args:
            number (int): number in bytes to be converted.

        Returns:
            (float): number of the unit chosen in the constructor.
        """
        return number / (1024 ** self._DATA_UNITS[self._value_unit])

    def _write_csv(self, data: Dict[str, Any]) -> None:
        """Write the collected data in a CSV file.

        Args:
            data (Dict[str, Any]): dictionary containing the data collected from the file.
        """
        header = not os.path.isfile(self._csv_file)
        with open(self._csv_file, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            if header:
                csv_writer.writerow(list(data))

            csv_writer.writerow(list(data.values()))
        logger.debug(f'Added new entry in {self._csv_file}')
