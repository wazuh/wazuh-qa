# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta


class TimeMachine:
    """Context manager that goes forward/back in time and comes back to real time once it finishes its instance."""
    total_time_spent = 0

    def __init__(self, timedelta_):
        """
        Save time frame given by user.

        Args:
            timedelta_ : Time frame.
        """
        self.time_delta = timedelta_

    def __enter__(self):
        """Call travel_to_future function with saved timedelta as argument."""
        self.travel_to_future(self.time_delta)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Call travel_to_future again before exiting with a negative timedelta."""
        self.travel_to_future(self.time_delta * -1)

    @staticmethod
    def _linux_set_time(datetime_):
        """
        Change date and time in a Linux system.

        Args:
            datetime_ : New date and time to set.
        """
        import shlex
        subprocess.call(shlex.split("timedatectl set-ntp false"))
        subprocess.call(shlex.split("date -s " + datetime_.isoformat() + " +%Y-%m-%dT%H:%M:%S.%s"))
        subprocess.call(shlex.split("hwclock -w"))

    @staticmethod
    def _win_set_time(datetime_):
        """
        Change date and time in a Windows system.

        Args:
            datetime_ : New date and time to set.
        """
        subprocess.call(["powershell.exe", "Set-Date", "-Date", f'"{datetime_.strftime("%d/%m/%Y %H:%M:%S")}"'])

    @staticmethod
    def _solaris_set_time(datetime_):
        """
        Change date and time in a Linux system.

        Args:
            datetime_ : New date and time to set.
        """
        solaris_time_format = "%m%d%H%M%Y.%S"
        os.system("date '%s'" % datetime_.strftime(solaris_time_format))

    @staticmethod
    def _macos_set_time(datetime_):
        """
        Change date and time in a MacOS system.

        Args:
            datetime_ : New date and time to set.
        """
        # {month}{day}{hour}{minute}{year}.{seconds}
        os.system('date ' + '-u ' + datetime_.strftime("%m%d%H%M%Y.%S"))

    @staticmethod
    def travel_to_future(time_delta, back_in_time=False):
        """
        Check which system are we running this code in and calls its proper function.

        Args:
            time_delta : Time frame we want to skip. It can have a negative value.
            back_in_time (bool, optional): Go back in time the same time_delta interval. Default value is False.
        """
        # Save timedelta to be able to  travel back in time after the tests
        TimeMachine.total_time_spent += time_delta.total_seconds()
        now = datetime.utcnow() if sys.platform == 'darwin' else datetime.now()
        future = now + time_delta if not back_in_time else now - time_delta
        if sys.platform == 'linux':
            TimeMachine._linux_set_time(future)
        elif sys.platform == 'sunos5':
            TimeMachine._solaris_set_time(future)
        elif sys.platform == 'win32':
            TimeMachine._win_set_time(future)
        elif sys.platform == 'darwin':
            TimeMachine._macos_set_time(future)

    @staticmethod
    def time_rollback():
        TimeMachine.travel_to_future(timedelta(seconds=TimeMachine.total_time_spent), back_in_time=True)
        TimeMachine.total_time_spent = 0


class Timer(threading.Thread):

    def __init__(self, timeout=10, function=None, time_step=0.5):
        threading.Thread.__init__(self)
        self.timeout = timeout
        self.function = function
        self.time_step = time_step
        self._cancel = threading.Event()

    def run(self):
        max_iterations = int(self.timeout / self.time_step)
        for i in range(max_iterations):
            time.sleep(self.time_step)
            if self.is_canceled():
                return
        self.function()
        return

    def cancel(self):
        self._cancel.set()

    def is_canceled(self):
        return self._cancel.is_set()


def reformat_time(scan_time):
    """
    Transform scan_time to readable time.

    Args:
        scan_time (str): Time string.

    Returns:
        datetime: Datetime object with the string translated.
    """
    hour_format = '%H'
    colon = ''
    locale = ''
    if ':' in scan_time:
        colon = ':%M'
    if re.search('[a-zA-Z]', scan_time):
        locale = '%p'
        hour_format = '%I'
    cd = datetime.now()
    return datetime.replace(datetime.strptime(scan_time, hour_format + colon + locale),
                            year=cd.year, month=cd.month, day=cd.day)


def time_to_timedelta(time_):
    """
    Convert a string with time in seconds with `smhdw` suffixes allowed to `datetime.timedelta`.

    Args:
        time_ (str): String with time in seconds.
    Returns:
        timedelta: Timedelta object.
    """
    time_unit = time_[len(time_) - 1:]

    if time_unit.isnumeric():
        return timedelta(seconds=int(time_))

    time_value = int(time_[:len(time_) - 1])

    if time_unit == "s":
        return timedelta(seconds=time_value)
    elif time_unit == "m":
        return timedelta(minutes=time_value)
    elif time_unit == "h":
        return timedelta(hours=time_value)
    elif time_unit == "d":
        return timedelta(days=time_value)
    elif time_unit == "w":
        return timedelta(weeks=time_value)


def time_to_human_readable(time_):
    """
    Convert a time string like 5s or 2d into a human-readable string such as 5 seconds or 2 days

    Args:

    time_ (str): String with the time and the measurement unit

    Returns:
        human_readable_time (str): String in the new format, for example: 5 seconds
    """

    time_unit = time_[-1]

    human_readable_string = {
        's': ' seconds',
        'm': ' minutes',
        'h': ' houres',
        'd': ' days'
    }

    human_readable_time = time_.replace(time_unit, human_readable_string[time_unit])

    return human_readable_time


def unit_to_seconds(time_):
    """
    Convert a time string like 9m or 2d into another similar string in seconds

    Args:
        time_ (str): String with the time and the measurement unit

    Returns:
        seconds_time: String in the same format with units converted to seconds
    """

    seconds_equivalent = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400
    }

    time_unit = time_[-1]
    time_value = time_[:-1]

    new_value = int(time_value) * seconds_equivalent[time_unit]

    seconds_time = f'{new_value}s'

    return seconds_time


def time_to_seconds(time_):
    """
    Convert a string with format (1s, 1m, 1h, 1d, 1w) in number of seconds.

    Args:
        time_ (str): String (1s, 1m, 1h, 1d, 1w).

    Returns:
        time_value (int): Number of seconds.
    """
    time_unit = time_[len(time_) - 1:]

    time_value = int(time_[:len(time_) - 1])

    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}

    return time_value * units[time_unit]


def get_current_timestamp():
    """Get the current timestamp. For example: 1627028708.303002

    Returns:
        int: current timestamp.
    """
    return datetime.now().timestamp()


def interval_to_time_modifier(interval):
    """Convert a string with format (1s, 1m, 1h, 1d) to SQLite date modifier.

    Args:
        interval (str): Time interval string.

    Returns:
          str: SQLite date modifier.
    """
    interval_units_dict = {'s': 'seconds', 'm': 'minutes', 'h': 'hours', 'd': 'days'}
    time_value = interval[:-1]
    time_unit = interval[-1]
    return f"{time_value} {interval_units_dict[time_unit]}"


def parse_date_time_format(date_time):
    """Parse the specified date_time to return a common format.

    Args:
        date_time (str): Date time to parse.

    Returns:
        str: Date time in format '%Y-%m-%d %H:%M:%S'

    Raises:
        ValueError: If could not parse the specified date_time
    """
    regex_list = [
        {'regex': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})Z', 'append': ':00'},  # CPE format
        {'regex': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})', 'append': ''},  # RHEL Canonical, ALAS, MSU, Debian, NVD
        {'regex': r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})', 'append': ''}  # Arch
    ]

    for item in regex_list:
        match = re.compile(item['regex']).match(date_time)

        if match:
            return f"{match.group(1)} {match.group(2)}{item['append']}"

    ValueError(f"Could not parse the {date_time} datetime.")
