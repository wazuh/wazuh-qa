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
from copy import deepcopy
from struct import pack, unpack

from wazuh_testing import logger
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


class FileMonitor:

    def __init__(self, file_path, time_step=0.5):
        self.file_path = file_path
        self._position = 0
        self.time_step = time_step
        self._continue = False
        self._abort = False
        self._previous_event = None
        self._result = None
        self.timeout_timer = None
        self.extra_timer = None
        self.extra_timer_is_running = False

    def _monitor(self, callback=_callback_default, accum_results=1, update_position=True, timeout_extra=0,
                 encoding=None, error_message=''):
        """Wait for new lines to be appended to the file.
        A callback function will be called every time a new line is detected. This function must receive two
        positional parameters: a references to the FileMonitor object and the line detected.
        """
        previous_position = self._position
        if sys.platform == 'win32':
            encoding = None if encoding is None else encoding
        elif encoding is None:
            encoding = 'utf-8'
        self.extra_timer_is_running = False
        self._result = [] if accum_results > 1 or timeout_extra > 0 else None
        with open(self.file_path, encoding=encoding) as f:
            f.seek(self._position)
            while self._continue:
                if self._abort and not self.extra_timer_is_running:
                    self.stop()
                    if type(self._result) != list or accum_results != len(self._result):
                        logger.error(error_message)
                        raise TimeoutError()
                self._position = f.tell()
                line = f.readline()
                if not line:
                    f.seek(self._position)
                    time.sleep(self.time_step)
                else:
                    result = callback(line)
                    if result:
                        if type(self._result) == list:
                            self._result.append(result)
                            if accum_results == len(self._result):
                                if timeout_extra > 0 and not self.extra_timer_is_running:
                                    self.extra_timer = Timer(timeout_extra, self.stop)
                                    self.extra_timer.start()
                                    self.extra_timer_is_running = True
                                elif timeout_extra == 0:
                                    self.stop()
                        else:
                            self._result = result
                            if self._result:
                                self.stop()
            self._position = f.tell() if update_position else previous_position

    def start(self, timeout=-1, callback=_callback_default, accum_results=1, update_position=True, timeout_extra=0,
              encoding=None, error_message=''):
        """Start the file monitoring until the stop method is called."""
        if not self._continue:
            self._continue = True
            self._abort = False
            if timeout > 0:
                self.timeout_timer = Timer(timeout, self.abort)
                self.timeout_timer.start()
            self._monitor(callback=callback, accum_results=accum_results, update_position=update_position,
                          timeout_extra=timeout_extra, encoding=encoding, error_message=error_message)

        return self

    def stop(self):
        """Stop the file monitoring. It can be restart calling the start method."""
        self._continue = False
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer.join()
        if self.extra_timer and self.extra_timer_is_running:
            self.extra_timer.cancel()
            self.extra_timer_is_running = False
        return self

    def abort(self):
        """Abort because of timeout."""
        self._abort = True
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

    def get_results(self, callback=_callback_default, accum_results=1, timeout=-1, update_position=True):
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

        Returns
        -------
        list of any or any
            It can return either a list of any type or simply any type. If `accum_results > 1`, it will be a list.
        """
        result_list = []
        timer = 0.0
        time_wait = 0.1
        position = 0
        while len(result_list) != accum_results:
            if timer >= timeout:
                self.abort()
                break
            try:
                if update_position:
                    item = callback(self._queue.get(block=True, timeout=self._time_step))
                else:
                    item = callback(self._queue.peek(position=position, block=True, timeout=self._time_step))
                    position += 1
                if item is not None:
                    result_list.append(item)
            except queue.Empty:
                time.sleep(time_wait)
                timer += self._time_step + time_wait

        if len(result_list) == 1:
            return result_list[0]
        else:
            return result_list

    def start(self, timeout=-1, callback=_callback_default, accum_results=1, update_position=True):
        """Start the queue monitoring until the stop method is called."""
        if not self._continue:
            self._continue = True
            self._abort = False

            while self._continue:
                if self._abort:
                    raise TimeoutError()
                result = self.get_results(callback=callback, accum_results=accum_results, timeout=timeout,
                                          update_position=update_position)
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
        aux_queue.queue = deepcopy(self.queue)
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
