# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import csv
import logging
from datetime import datetime
from os.path import join, isfile
from threading import Thread, Event
from time import sleep
from sys import platform
from tempfile import gettempdir
import psutil

MONITOR_LIST = []

logger = logging.getLogger('wazuh-monitor')
logger.setLevel(logging.INFO)


class Monitor:
    def __init__(self, process_name, value_unit='B', time_step=1, dst_dir=gettempdir()):
        self.process_name = process_name
        self.value_unit = value_unit
        self.time_step = time_step
        self.data_units = {'B': 0, 'KB': 1, 'MB': 2}
        self.platform = platform
        self.dst_dir = dst_dir
        self.pid = None
        self.event = None
        self.thread = None
        self.set_pid(self.process_name)
        self.csv_file = join(self.dst_dir, f'{self.process_name}.csv')

    def set_pid(self, process_name):
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
        # Since these values may not be computed in SunOS or BSD, they are set to 0 as default value
        info = {'Read_Ops': 0, 'Write_Ops': 0, f'Disk_Read({self.value_unit})': 0.0,
                f'Disk_Written({self.value_unit})': 0.0, 'Disk(%)': 0.0, 'PID': self.pid}

        def unit_conversion(x):
            return x / (1024 ** self.data_units[self.value_unit])

        with proc.oneshot():
            info['Timestamp'] = datetime.now().strftime('%H:%M:%S')
            info['CPU(%)'] = proc.cpu_percent(interval=0.1)

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

        info.update({key: round(value, 2) for key, value in info.items() if isinstance(value, (int, float))})
        logger.debug(f'Recollected data for process {proc.pid}')
        return info

    def _write_csv(self, data):

        header = not isfile(self.csv_file)
        with open(self.csv_file, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            if header:
                csv_writer.writerow(list(data))

            csv_writer.writerow(list(data.values()))
        logger.debug(f'Added new entry in {self.csv_file}')

    def _monitor_process(self):
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
        self.event = Event()
        self.thread = Thread(target=self._monitor_process)
        self.thread.start()

    def start(self):
        self.run()
        logger.info(f'Started monitoring process {self.process_name} ({self.pid})')

    def shutdown(self):
        self.event.set()
        self.thread.join()
