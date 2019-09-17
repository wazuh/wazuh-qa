# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from _datetime import datetime
import sys
import time
import threading


class TimeMachine:
    """ Context manager that goes forward/back in time and comes back to real time once it finishes its instance
    """

    def __init__(self, timedelta):
        """ Saves time frame given by user

        :param timedelta: time frame
        :type timedelta: timedelta
        """
        self.time_delta = timedelta

    def __enter__(self):
        """ Calls travel_to_future function with saved timedelta as argument
        """
        self.travel_to_future(self.time_delta)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """ Calls travel_to_future again before exiting with a negative timedelta
        """
        self.travel_to_future(self.time_delta * -1)

    @staticmethod
    def _linux_set_time(time_):
        """ Changes date and time in a Linux system

        :param time_: new date and time to set
        :type time_: time
        """
        import subprocess
        import shlex

        subprocess.call(shlex.split("timedatectl set-ntp false"))
        subprocess.call(shlex.split("sudo date -s '%s'" % time_))

    @staticmethod
    def _win_set_time(time_):
        """ Changes date and time in a Windows system

        :param time_: new date and time to set
        :type time_: time
        """
        import os
        date_ = str(time_.date())
        time_ = str(time_.time()).split('.')
        time_ = time_[0]
        os.system('date ' + date_)
        os.system('time ' + time_)

    @staticmethod
    def travel_to_future(time_delta):
        """ Checks which system are we running this code in and calls its proper function

        :param time_delta: time frame we want to skip. It can have a negative value
        :type time_delta: timedelta
        """
        future = datetime.now() + time_delta
        if sys.platform == 'linux2' or sys.platform == 'linux':
            TimeMachine._linux_set_time(future.isoformat())
        elif sys.platform == 'win32':
            TimeMachine._win_set_time(future)


def truncate_file(file_path):
    with open(file_path, 'w'):
        pass


def wait_for_condition(condition_checker, args=None, kwargs=None, timeout=-1):
    args = [] if args is None else args
    kwargs = {} if kwargs is None else kwargs
    time_step = 0.5
    max_iterations = timeout / time_step
    begin = time.time()
    iterations = 0
    while not condition_checker(*args, **kwargs):
        if timeout != -1 and iterations > max_iterations:
            raise TimeoutError()
        iterations += 1
        time.sleep(time_step)


def _callback_default(line):
    print(line)
    return None


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


class FileMonitor:

    def __init__(self, file_path, time_step=0.5):
        self.file_path = file_path
        self._position = 0
        self.time_step = time_step
        self._continue = False
        self._abort = False
        self._result = None
        self.timer = None

    def _monitor(self, callback=_callback_default, accum_results=1):
        """Wait for new lines to be appended to the file.

        A callback function will be called every time a new line is detected. This function must receive two
        positional parameters: a references to the FileMonitor object and the line detected.
        """
        self._result = [] if accum_results > 1 else None
        with open(self.file_path) as f:
            print(f"Seeking to: {self._position}")
            f.seek(self._position)
            while self._continue:
                if self._abort:
                    self.stop()
                    raise TimeoutError()
                self._position = f.tell()
                line = f.readline()
                if not line:
                    f.seek(self._position)
                    time.sleep(self.time_step)
                else:
                    result = callback(line)
                    if result:
                        if accum_results > 1:
                            self._result.append(result)
                            if accum_results == len(self._result):
                                self.stop()
                        else:
                            self._result = result
                            if self._result:
                                self.stop()

            self._position = f.tell()

    def start(self, timeout=-1, callback=_callback_default, accum_results=1):
        """Start the file monitoring until the stop method is called"""
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                print(f"Pongo el temporizador a {timeout} segundos")
                self.timer = Timer(timeout, self.abort)
                self.timer.start()
            self._monitor(callback=callback, accum_results=accum_results)

        return self

    def stop(self):
        """Stop the file monitoring. It can be restart calling the start method"""
        self._continue = False
        if self.timer:
            self.timer.cancel()
            self.timer.join()
        return self

    def abort(self):
        """Abort because of timeout"""
        print("Aborto por timeout!!!!!!!!!!!")
        self._abort = True
        return self

    def result(self):
        return self._result
