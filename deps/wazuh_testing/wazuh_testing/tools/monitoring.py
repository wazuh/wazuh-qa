# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# Unix only modules

try:
    import grp
    import pwd
except ModuleNotFoundError:
    pass

import os
import queue
import socket
import socketserver
import sys
import threading
import time
from collections import defaultdict
from copy import copy
from multiprocessing import Process, Manager
from struct import pack, unpack

import yaml

from wazuh_testing import logger
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.time import Timer


def wazuh_unpack(data, format_: str = "<I"):
    """Unpack data with a given header. Using Wazuh header by default.

    Parameters
    ----------
    data : bytes
        Binary data to unpack
    format_ : str, optional
        Format used to unpack data. Default "<I"

    Returns
    -------
    int
        Unpacked value
    """
    return unpack(format_, data)[0]


def wazuh_pack(data, format_: str = "<I"):
    """Pack data with a given header. Using Wazuh header by default.

    Parameters
    ----------
    data : int
        Int number to pack
    format_ : str, optional
        Format used to pack data. Default "<I"

    Returns
    -------
    bytes
        Packed value
    """
    return pack(format_, data)


def wait_for_condition(condition_checker, args=None, kwargs=None, timeout=-1):
    """Wait for a given condition to check.

    Parameters
    ----------
    condition_checker : callable
        Function that checks a condition.
    args :  list, optional
        List of positional arguments. Default `None`
    kwargs : dict, optional
        Dict of non positional arguments. Default `None`
    timeout : int, optional
        Time to wait. Default `-1`

    Raises
    ------
    TimeoutError
        If `timeout` is not -1 and there have been more iterations that the max allowed.
    """
    args = [] if args is None else args
    kwargs = {} if kwargs is None else kwargs
    time_step = 0.5
    max_iterations = timeout / time_step
    iterations = 0
    while not condition_checker(*args, **kwargs):
        if timeout != -1 and iterations > max_iterations:
            raise TimeoutError()
        iterations += 1
        time.sleep(time_step)


def _callback_default(line):
    print(line)
    return None


class FileTailer:

    def __init__(self, file_path, encoding=None, time_step=0.5):
        self.file_path = file_path
        self._position = 0
        self.time_step = time_step
        self._queue = Queue()
        self.event = threading.Event()
        self.thread = None
        if sys.platform == 'win32':
            self.encoding = None if encoding is None else encoding
        elif encoding is None:
            self.encoding = 'utf-8'

    def __copy__(self):
        new_tailer = FileTailer(self.file_path)
        for attr, value in vars(self).items():
            if attr == 'file_path':
                continue
            elif attr != '_queue':
                setattr(new_tailer, attr, value)
            else:
                new_queue = Queue()
                new_queue.queue = copy(getattr(self, attr).queue)
                setattr(new_tailer, attr, new_queue)
        return new_tailer

    @property
    def queue(self):
        return self._queue

    def add_item(self, item):
        self._queue.put(item)

    def start(self):
        self.run()

    def run(self):
        self.event = threading.Event()
        self.thread = threading.Thread(target=self._tail_forever)
        self.thread.start()

    def shutdown(self):
        self.event.set()
        self.thread.join()

    def _tail_forever(self):
        """Wait for new lines to be appended to the file."""
        with open(self.file_path, encoding=self.encoding, errors='backslashreplace') as f:
            f.seek(self._position)
            while not self.event.is_set():
                line = f.readline()
                if not line:
                    f.seek(self._position)
                    time.sleep(self.time_step)
                else:
                    self.add_item(line)
                self._position = f.tell()


class FileMonitor:

    def __init__(self, file_path, time_step=0.5):
        self.tailer = FileTailer(file_path, time_step=time_step)
        self._result = None
        self._time_step = time_step

    def start(self, timeout=-1, callback=_callback_default, accum_results=1, update_position=True, timeout_extra=0,
              error_message='', encoding=None):
        """Start the file monitoring until the stop method is called."""
        try:
            tailer = self.tailer if update_position else copy(self.tailer)

            if encoding is not None:
                tailer.encoding = encoding
            tailer.start()

            monitor = QueueMonitor(tailer.queue, time_step=self._time_step)
            self._result = monitor.start(timeout=timeout, callback=callback, accum_results=accum_results,
                                         update_position=update_position, timeout_extra=timeout_extra,
                                         error_message=error_message).result()
        finally:
            tailer.shutdown()

        return self

    def result(self):
        return self._result


class SocketController:

    def __init__(self, path, timeout=30, connection_protocol='TCP'):
        """Create a new unix socket or connect to a existing one.

        Parameters
        ----------
        path : str
            Path where the file will be created.
        timeout : int, optional
            Socket's timeout, 0 for non-blocking mode.
        connection_protocol : str
            Flag that indicates if the connection is TCP (SOCK_STREAM) or UDP (SOCK_DGRAM).

        Raises
        ------
        Exception
            If the socket connection failed.
        """
        self.path = path
        if connection_protocol.lower() == 'tcp':
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        elif connection_protocol.lower() == 'udp':
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            wait_for_condition(os.path.exists, args=[self.path], timeout=3)
        else:
            raise TypeError('Invalid connection protocol detected. Valid ones are TCP or UDP')

        try:
            self.sock.settimeout(timeout)
            self.sock.connect(self.path)
        except OSError as e:
            if os.path.exists(path):
                os.unlink(path)
            self.sock.bind(self.path)
            os.chmod(self.path, 0o666)

    def close(self):
        """Close the socket gracefully."""
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def send(self, messages, size=False):
        """Send a list of messages to the socket.

        Parameters
        ----------
        messages : list
            List of messages to be sent.
        size : bool, optional
            Flag that indicates if the header of the message includes the size of the message.
            (Analysis doesn't need the size, wazuh-db does). Default `False`

        Returns
        -------
        list
            List of sizes of the sent messages.
        """
        output = list()
        for message_ in messages:
            msg_bytes = message_.encode()
            try:
                if size:
                    output.append(self.sock.sendall(wazuh_pack(len(msg_bytes)) + msg_bytes))
                else:
                    output.append(self.sock.sendto(msg_bytes, self.path))
            except OSError as e:
                raise e

        return output

    def receive(self, total_messages=1):
        """Receive a specified number of messages from the socket.

        Parameters
        ----------
        total_messages : int, optional
            Total messages to be received. Default `1`

        Returns
        -------
        list
            Socket messages.
        """
        output = list()
        for _ in range(0, total_messages):
            try:
                size = wazuh_unpack(self.sock.recv(4, socket.MSG_WAITALL))
                output.append(self.sock.recv(size, socket.MSG_WAITALL).decode().rstrip('\x00'))
            except OSError:
                try:
                    self.sock.listen(1)
                    conn, addr = self.sock.accept()
                    size = wazuh_unpack(conn.recv(4, socket.MSG_WAITALL))
                    output.append(conn.recv(size, socket.MSG_WAITALL).decode().rstrip('\x00'))
                except OSError as e:
                    raise e

        return output

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SocketMonitor:

    def __init__(self, path, connection_protocol='TCP', controller=None, socket_timeout=30):
        """Create a new unix socket or connect to a existing one.

        Parameters
        ----------
        path : str
            Path where the file will be created.
        connection_protocol : str, optional
            Flag that indicates if the connection is TCP (SOCK_STREAM) or UDP (SOCK_DGRAM).
        controller : SocketController, optional
            Already initialized SocketController to avoid creating a new one. Useful in case of monitoring
            the same socket where messages are being sent.
        socket_timeout : int, optional
            Timeout in seconds to abort a recv operation from the socket.

        Raises
        ------
        Exception
            If the socket connection failed.
        """
        self._continue = False
        self._abort = False
        self._result = None
        self.timeout_timer = None
        self.path = path
        if not controller:
            self.controller = SocketController(path=path, connection_protocol=connection_protocol,
                                               timeout=socket_timeout)
        else:
            self.controller = controller

    def start(self, timeout=-1, callback=_callback_default, accum_results=1):
        """Start the socket monitoring with specified callback.

        Parameters
        ----------
        timeout : int, optional
            Timeout of the operation. Default `-1`
        callback : callable, optional
            Callable function that accepts a specified param. Default ``_callback_default``
        accum_results : int, optional
            Expected number of messages. Default `1`

        Returns
        -------
        list
            Socket messages.
        """
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timeout_timer = Timer(timeout, self.abort)
                self.timeout_timer.start()
            while self._continue:
                if self._abort:
                    self.stop()
                    raise TimeoutError()
                for message in self.controller.receive(accum_results):
                    result = callback(message)
                    if result:
                        self._add_results(result, accum_results)
        return self

    def _add_results(self, result, accum_results):
        if accum_results > 1:
            self._result.append(result)
            accum_results == len(self._result) and self.stop()
        else:
            self._result = result
            self._result and self.stop()

    def result(self):
        """Return the monitored socket messages."""
        return self._result

    def close(self):
        """Close the socket gracefully."""
        self.controller.close()

    def stop(self):
        """Stop the socket monitoring. It can be restarted calling the start method."""
        self._continue = False
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer.join()
        return self

    def abort(self):
        """Raise a timeout exception if the operation takes more time that the specified timeout."""
        self._abort = True
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class QueueMonitor:
    def __init__(self, queue_item, time_step=0.5):
        """Create a new instance to monitor any given queue.

        Parameters
        ----------
        queue_item : Queue
            Queue to monitor.
        time_step : float, optional
            Fraction of time to wait in every get. Default `0.5`
        """
        self._queue = queue_item
        self._continue = False
        self._abort = False
        self._result = None
        self._time_step = time_step

    def get_results(self, callback=_callback_default, accum_results=1, timeout=-1, update_position=True,
                    timeout_extra=0):
        """Get as many matched results as `accum_results`.

        Parameters
        ----------
        callback : callable, optional
            Callback function to filter results.
        accum_results : int, optional
            Number of results to get. Default `1`
        timeout : int, optional
            Maximum timeout. Default `-1`
        update_position : bool, optional
            True if we pop items from the queue once they are read. False otherwise. Default `True`
        timeout_extra : int, optional
            Grace period to fetch more events than specified in `accum_results`. Default: 0.

        Returns
        -------
        list of any or any
            It can return either a list of any type or simply any type. If `accum_results > 1`, it will be a list.
        """
        result_list = []
        timer = 0.0
        time_wait = 0.1
        position = 0
        extra_timer_is_running = False
        extra_timer = 0.0
        while len(result_list) != accum_results or extra_timer_is_running:
            if timer >= timeout and not extra_timer_is_running:
                self.abort()
                break
            if extra_timer >= timeout_extra > 0:
                self.stop()
                break
            try:
                if update_position:
                    item = callback(self._queue.get(block=True, timeout=self._time_step))
                else:
                    item = callback(self._queue.peek(position=position, block=True, timeout=self._time_step))
                    position += 1
                if item is not None:
                    result_list.append(item)
                    if len(result_list) == accum_results and timeout_extra > 0 and not extra_timer_is_running:
                        extra_timer_is_running = True
            except queue.Empty:
                time.sleep(time_wait)
                timer += self._time_step + time_wait
                if extra_timer_is_running:
                    extra_timer += self._time_step + time_wait

        if len(result_list) == 1:
            return result_list[0]
        else:
            return result_list

    def start(self, timeout=-1, callback=_callback_default, accum_results=1, update_position=True, timeout_extra=0,
              error_message=''):
        """Start the queue monitoring until the stop method is called."""
        if not self._continue:
            self._continue = True
            self._abort = False

            while self._continue:
                if self._abort:
                    self.stop()
                    if error_message:
                        logger.error(error_message)
                        logger.error(f"Results accumulated: "
                                     f"{len(self._result) if isinstance(self._result, list) else 0}")
                        logger.error(f"Results expected: {accum_results}")
                    raise TimeoutError()
                result = self.get_results(callback=callback, accum_results=accum_results, timeout=timeout,
                                          update_position=update_position, timeout_extra=timeout_extra)
                if result and not self._abort:
                    self._result = result
                    if self._result:
                        self.stop()

        return self

    def stop(self):
        """Stop the queue monitoring. It can be restart calling the start method."""
        self._continue = False
        return self

    def abort(self):
        """Abort because of timeout."""
        self._abort = True
        return self

    def result(self):
        """Return the current result."""
        return self._result

    def get_queue(self):
        """Return the monitored queue."""
        return self._queue


class Queue(queue.Queue):
    def peek(self, *args, position=0, **kwargs):
        """Peek any given position without modifying the queue status.

        The difference between `peek` and `get` is `peek` pops the item and `get` does not.

        Parameters
        ----------
        position : int, optional
            Element of the queue to return. Default `0`

        Returns
        -------
        any
            Any item in the given position.
        """
        aux_queue = queue.Queue()
        aux_queue.queue = copy(self.queue)
        for _ in range(position):
            aux_queue.get(*args, **kwargs)
        return aux_queue.get(*args, **kwargs)


if hasattr(socketserver, 'ThreadingUnixStreamServer'):
    class StreamServer(socketserver.ThreadingUnixStreamServer):

        def shutdown_request(self, request):
            pass


    class StreamHandler(socketserver.BaseRequestHandler):

        def forward(self, data):
            # Create a socket (SOCK_STREAM means a TCP socket)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as forwarded_sock:
                # Connect to server and send data
                forwarded_sock.connect(self.server.mitm.forwarded_socket_path)
                forwarded_sock.sendall(wazuh_pack(len(data)) + data)

                # Receive data from the server and shut down
                size = wazuh_unpack(self.recvall(forwarded_sock, 4, socket.MSG_WAITALL))
                response = self.recvall(forwarded_sock, size, socket.MSG_WAITALL)

                return response

        def recvall(self, sock: socket.socket, size: int, mask: int):
            buffer = bytearray()
            while len(buffer) < size:
                try:
                    data = sock.recv(size - len(buffer), mask)
                    if not data:
                        break
                    buffer.extend(data)
                except socket.timeout:
                    if self.server.mitm.event.is_set():
                        break
            return bytes(buffer)

        def handle(self):
            self.request.settimeout(1)
            while not self.server.mitm.event.is_set():
                header = self.recvall(self.request, 4, socket.MSG_WAITALL)
                if not header:
                    break
                size = wazuh_unpack(header)
                data = self.recvall(self.request, size, socket.MSG_WAITALL)
                if not data:
                    break

                response = self.server.mitm.handler_func(data) if self.server.mitm.handler_func else self.forward(data)

                self.server.mitm.put_queue((data.rstrip(b'\x00'), response.rstrip(b'\x00')))

                self.request.sendall(wazuh_pack(len(response)) + response)


    class DatagramHandler(socketserver.BaseRequestHandler):

        def forward(self, data):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as forwarded_sock:
                forwarded_sock.sendto(data, self.server.mitm.forwarded_socket_path)

        def handle(self):
            data = self.request[0]

            self.server.mitm.handler_func(data) if self.server.mitm.handler_func else self.forward(data)

            self.server.mitm.put_queue(data.rstrip(b'\x00'))


    class DatagramServer(socketserver.UnixDatagramServer):

        def shutdown_request(self, request):
            pass


    class ManInTheMiddle:

        def __init__(self, socket_path, mode='TCP', func: callable = None):
            """Create a MITM for the socket `socket_path`.

            Parameters
            ----------
            socket_path : str
                Path of the socket to be replaced.
            mode : str
                It can be either 'TCP' or 'UDP'. Default `'TCP'`
            func : callable
                Function to be applied to every data before sending it.
            """
            self.listener_socket_path = socket_path
            self.forwarded_socket_path = f'{socket_path}.original'
            os.rename(self.listener_socket_path, self.forwarded_socket_path)
            self.listener_class = StreamServer if mode == 'TCP' else socketserver.UnixDatagramServer
            self.handler_class = StreamHandler if mode == 'TCP' else DatagramHandler
            self.handler_func = func
            self.mode = mode
            self.listener = None
            self.thread = None
            self.event = threading.Event()
            self._queue = Queue()

        def run(self, *args):
            self.listener = self.listener_class(self.listener_socket_path, self.handler_class)
            self.listener.mitm = self

            # set proper socket permissions
            uid = pwd.getpwnam('ossec').pw_uid
            gid = grp.getgrnam('ossec').gr_gid
            os.chown(self.listener_socket_path, uid, gid)
            os.chmod(self.listener_socket_path, 0o660)

            self.thread = threading.Thread(target=self.listener.serve_forever)
            self.thread.start()

        def start(self):
            self.run()

        def shutdown(self):
            self.listener.shutdown()
            self.listener.socket.close()
            self.event.set()
            os.remove(self.listener_socket_path)
            os.rename(self.forwarded_socket_path, self.listener_socket_path)

        @property
        def queue(self):
            return self._queue

        def put_queue(self, item):
            self._queue.put(item)


def threaded(fn):
    """Wrapper for enable multiprocessing inside a class

    Parameters
    ----------
    fn : callable
        Function to be executed in a new thread

    Returns
    -------
    wrapper
    """

    def wrapper(*args, **kwargs):
        thread = Process(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread

    return wrapper


def callback_generator(regex):
    import re

    def new_callback(line):
        match = re.match(rf'{regex}', line)
        if match:
            return line
        return None

    return new_callback


class HostMonitor:

    def __init__(self, inventory_path, messages_path, tmp_path, time_step=0.5):
        """Create a new instance to monitor any given file in any specified host.

        Parameters
        ----------
        inventory_path : str
            Path to the hosts's inventory file.
        messages_path : str
            Path to the file where the callbacks, paths and hosts to be monitored are specified.
        tmp_path : str
            Path to the temporal files.
        time_step : float, optional
            Fraction of time to wait in every get. Default `0.5`.
        """
        self.host_manager = HostManager(inventory_path=inventory_path)
        self._queue = Manager().Queue()
        self._result = defaultdict(list)
        self._time_step = time_step
        self._file_monitors = list()
        self._monitored_files = set()
        self._file_content_collectors = list()
        self._tmp_path = tmp_path
        try:
            os.mkdir(self._tmp_path)
        except OSError:
            pass
        with open(messages_path, 'r') as f:
            self.test_cases = yaml.safe_load(f)

    def run(self):
        """This method creates and destroy the needed processes for the messages founded in messages_path.
        It creates one file composer (process) for every file to be monitored in every host."""
        for host, payload in self.test_cases.items():
            self._monitored_files.update({case['path'] for case in payload})
            if len(self._monitored_files) == 0:
                raise AttributeError('There is no path to monitor. Exiting...')
            for path in self._monitored_files:
                output_path = f'{host}_{path.split("/")[-1]}.tmp'
                self._file_content_collectors.append(self.file_composer(host=host, path=path, output_path=output_path))
                logger.debug(f'Add new file composer process for {host} and path: {path}')
                self._file_monitors.append(self._start(host=host, payload=payload, path=output_path))
                logger.debug(f'Add new file monitor process for {host} and path: {path}')

        while True:
            if not any([handler.is_alive() for handler in self._file_monitors]):
                for handler in self._file_monitors:
                    handler.join()
                for file_collector in self._file_content_collectors:
                    file_collector.terminate()
                    file_collector.join()
                self.clean_tmp_files()
                break
            time.sleep(self._time_step)
        self.check_result()

    @threaded
    def file_composer(self, host, path, output_path):
        """Collects the file content of the specified path in the desired host and append it to the output_path file.
        Simulates the behavior of tail -f and redirect the output to output_path.

        Parameters
        ----------
        host : str
            Hostname.
        path : str
            Host file path to be collect.
        output_path : str
            Output path of the content collected from the remote host path.
        """
        try:
            truncate_file(os.path.join(self._tmp_path, output_path))
        except FileNotFoundError:
            pass
        logger.debug(f'Starting file composer for {host} and path: {path}. '
                     f'Composite file in {os.path.join(self._tmp_path, output_path)}')
        while True:
            with open(os.path.join(self._tmp_path, output_path), "r+") as file:
                content = self.host_manager.get_file_content(host, path).split('\n')
                file_content = file.read().split('\n')
                for new_line in content:
                    if new_line == '':
                        continue
                    if new_line not in file_content:
                        file.write(f'{new_line}\n')
            time.sleep(self._time_step)

    @threaded
    def _start(self, host, payload, path, encoding=None):
        """Start the file monitoring until the QueueMonitor returns an string or TimeoutError.

        Parameters
        ----------
        host : str
            Hostname
        payload : list of dict
            Contains the message to be found and the timeout for it.
        path : str
            Path where it must search for the message.
        encoding : str
            Encoding of the file.

        Returns
        -------
        instance of HostMonitor
        """
        tailer = FileTailer(os.path.join(self._tmp_path, path), time_step=self._time_step)
        try:
            if encoding is not None:
                tailer.encoding = encoding
            tailer.start()
            for case in payload:
                logger.debug(f'Starting QueueMonitor for {host} and message: {case["regex"]}')
                monitor = QueueMonitor(tailer.queue, time_step=self._time_step)
                try:
                    self._queue.put({host: monitor.start(timeout=case['timeout'],
                                                         callback=callback_generator(case['regex'])
                                                         ).result().strip('\n')})
                except TimeoutError:
                    self._queue.put({
                        host: TimeoutError(f'Did not found the expected callback in {host}: {case["regex"]}')})
                logger.debug(f'Finishing QueueMonitor for {host} and message: {case["regex"]}')
        finally:
            tailer.shutdown()

        return self

    def result(self):
        """Get the result of HostMonitor

        Returns
        -------
        dict
            Dict that contains the host as the key and a list of messages as the values
        """
        return self._result

    def check_result(self):
        """Check if a TimeoutError occurred."""
        logger.debug(f'Checking results...')
        while not self._queue.empty():
            result = self._queue.get(block=True)
            for host, msg in result.items():
                if isinstance(msg, TimeoutError):
                    raise msg
                logger.debug(f'Received from {host} the expected message: {msg}')
                self._result[host].append(msg)

    def clean_tmp_files(self):
        """Remove tmp files."""
        logger.debug(f'Cleaning temporal files...')
        for file in os.listdir(self._tmp_path):
            os.remove(os.path.join(self._tmp_path, file))
