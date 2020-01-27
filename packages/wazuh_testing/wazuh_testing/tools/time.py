# Copyright (C) 2015-2019, Wazuh Inc.
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
    def __init__(self, timedelta):
        """
        Save time frame given by user.

        Parameters
        ----------
        timedelta : timedelta
            Time frame.
        """
        self.time_delta = timedelta

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

        Parameters
        ----------
        datetime_ : time
            New date and time to set.
        """
        import shlex
        subprocess.call(shlex.split("timedatectl set-ntp false"))
        subprocess.call(shlex.split("sudo date -s " + str(datetime_) + " +%Y-%m-%dT%H:%M:%S.%s"))
        subprocess.call(shlex.split("sudo hwclock -w"))

    @staticmethod
    def _win_set_time(datetime_):
        """
        Change date and time in a Windows system.

        Parameters
        ----------
        datetime_ : time
            New date and time to set.
        """
        os.system('date ' + datetime_.strftime("%d-%m-%Y"))
        os.system('time ' + datetime_.strftime("%H:%M:%S"))

    @staticmethod
    def _solaris_set_time(datetime_):
        """
        Change date and time in a Linux system.

        Parameters
        ----------
        datetime_ : time
            New date and time to set.
        """
        solaris_time_format = "%m%d%H%M%Y.%S"
        os.system("date '%s'" % datetime_.strftime(solaris_time_format))

    @staticmethod
    def _macos_set_time(datetime_):
        """
        Change date and time in a MacOS system.

        Parameters
        ----------
        datetime_ : time
            New date and time to set.
        """
        # {month}{day}{hour}{minute}{year}
        os.system('date ' + '-u ' + datetime_.strftime("%m%d%H%M%Y"))

    @staticmethod
    def travel_to_future(time_delta, back_in_time=False):
        """
        Check which system are we running this code in and calls its proper function.

        Parameters
        ----------
        time_delta : timedelta
            Time frame we want to skip. It can have a negative value.
        """
        #Save timedelta to be able to  travel back in time after the tests
        TimeMachine.total_time_spent += time_delta.seconds
        now = datetime.utcnow() if sys.platform == 'darwin' else datetime.now()
        future = now + time_delta if not back_in_time else now - time_delta
        if sys.platform == 'linux':
            TimeMachine._linux_set_time(future.isoformat())
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

    Parameters
    ----------
    scan_time : str
        Time string.

    Returns
    -------
    datetime
        Datetime object with the string translated.
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


def time_to_timedelta(time):
    """
    Convert a string with time in seconds with `smhdw` suffixes allowed to `datetime.timedelta`.

    Parameters
    ----------
    time : str
        String with time in seconds.

    Returns
    -------
    timedelta
        Timedelta object.
    """
    time_unit = time[len(time) - 1:]

    if time_unit.isnumeric():
        return timedelta(seconds=int(time))

    time_value = int(time[:len(time) - 1])

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