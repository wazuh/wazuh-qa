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
        with open(self.file_path, encoding=encoding, errors='backslashreplace') as f:
            f.seek(self._position)
            while self._continue:
                if self._abort and not self.extra_timer_is_running:
                    self.stop()
                    if not isinstance(self._result, list) or accum_results != len(self._result):
                        if error_message:
                            logger.error(error_message)
                            logger.error(f"Results accumulated: "
                                         f"{len(self._result) if isinstance(self._result, list) else 0}")
                            logger.error(f"Results expected: {accum_results}")
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

    def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', timeout=30):
        """Create a new unix socket or connect to a existing one.

        Parameters
        ----------
        address : str or Tuple(str, int)
            Address of the socket, the format of the address depends on the type. A regular file path for AF_UNIX or a
            Tuple(HOST, PORT) for AF_INET
        family : str
            Family type of socket to connect to, AF_UNIX for unix sockets or AF_INET for port sockets.
        connection_protocol : str
            Flag that indicates if the connection is TCP (SOCK_STREAM) or UDP (SOCK_DGRAM).
        timeout : int, optional
            Socket's timeout, 0 for non-blocking mode.

        Raises
        ------
        Exception
            If the socket connection failed.
        """
        self.address = address

        # Set socket family
        if family == 'AF_UNIX':
            self.family = socket.AF_UNIX
        elif family == 'AF_INET':
            self.family = socket.AF_INET
        else:
            raise TypeError(f'Invalid family type detected: {family}. Valid ones are AF_UNIX or AF_INET')

        # Set socket protocol
        if connection_protocol.lower() == 'tcp':
            self.protocol = socket.SOCK_STREAM
        elif connection_protocol.lower() == 'udp':
            self.protocol = socket.SOCK_DGRAM
        else:
            raise TypeError(f'Invalid connection protocol detected: {connection_protocol.lower()}. '
                            f'Valid ones are TCP or UDP')

        # Create socket object
        self.sock = socket.socket(family=self.family, type=self.protocol)

        # Connect only if protocol is TCP
        if self.protocol == socket.SOCK_STREAM:
            try:
                self.sock.settimeout(timeout)
                self.sock.connect(self.address)
            except socket.timeout as e:
                raise TimeoutError(f'Could not connect to socket {self.address} of family {self.family}')

    def close(self):
        """Close the socket gracefully."""
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def send(self, message, size=False):
        """Send a message to the socket.

        Parameters
        ----------
        message : str or bytes
            Message to be sent.
        size : bool, optional
            Flag that indicates if the header of the message includes the size of the message.
            (For example, Analysis doesn't need the size, wazuh-db does). Default `False`

        Returns
        -------
        int
            Size of the sent message
        """
        msg_bytes = message.encode() if isinstance(message, str) else message
        try:
            msg_bytes = wazuh_pack(len(msg_bytes)) + msg_bytes if size is True else msg_bytes
            if self.protocol == socket.SOCK_STREAM:  # TCP
                output = self.sock.sendall(msg_bytes)
            else:  # UDP
                output = self.sock.sendto(msg_bytes, self.address)
        except OSError as e:
            raise e

        return output

    def receive(self, size=False):
        """Receive a message from the socket.

        Parameters
        ----------
        size : bool, optional
            Flag that indicates if the header of the message includes the size of the message.
            (For example, Analysis doesn't need the size, wazuh-db does). Default `False`

        Returns
        -------
        bytes
            Socket message.
        """
        if size is True:
            size = wazuh_unpack(self.sock.recv(4, socket.MSG_WAITALL))
            output = self.sock.recv(size, socket.MSG_WAITALL)
        else:
            output = self.sock.recv(4096)
            if len(output) == 4096:
                while 1:
                    try:  # error means no more data
                        output += self.sock.recv(4096, socket.MSG_DONTWAIT)
                    except:
                        break

        return output

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


class StreamServerPort(socketserver.ThreadingTCPServer):
    pass


class DatagramServerPort(socketserver.ThreadingUDPServer):
    pass


if hasattr(socketserver, 'ThreadingUnixStreamServer'):

    class StreamServerUnix(socketserver.ThreadingUnixStreamServer):

        def shutdown_request(self, request):
            pass

    class DatagramServerUnix(socketserver.ThreadingUnixDatagramServer):

        def shutdown_request(self, request):
            pass


    class StreamHandler(socketserver.BaseRequestHandler):

        def unix_forward(self, data):
            """Default TCP unix socket forwarder for MITM servers."""
            # Create a socket context
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as forwarded_sock:
                # Connect to server and send data
                forwarded_sock.connect(self.server.mitm.forwarded_socket_path)
                forwarded_sock.sendall(wazuh_pack(len(data)) + data)

                # Receive data from the server and shut down
                size = wazuh_unpack(self.recvall_size(forwarded_sock, 4, socket.MSG_WAITALL))
                response = self.recvall_size(forwarded_sock, size, socket.MSG_WAITALL)

                return response

        def recvall_size(self, sock: socket.socket, size: int, mask: int):
            """Recvall with known size of the message."""
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

        def recvall(self, chunk_size: int = 4096):
            """Recvall without known size of the message."""
            received = self.request.recv(chunk_size)
            if len(received) == chunk_size:
                while 1:
                    try:  # error means no more data
                        received += self.request.recv(chunk_size, socket.MSG_DONTWAIT)
                    except:
                        break
            return received

        def default_wazuh_handler(self):
            """Default wazuh daemons TCP handler method for MITM server."""
            self.request.settimeout(1)
            while not self.server.mitm.event.is_set():
                header = self.recvall_size(self.request, 4, socket.MSG_WAITALL)
                if not header:
                    break
                size = wazuh_unpack(header)
                data = self.recvall_size(self.request, size, socket.MSG_WAITALL)
                if not data:
                    break

                response = self.unix_forward(data)

                self.server.mitm.put_queue((data.rstrip(b'\x00'), response.rstrip(b'\x00')))

                self.request.sendall(wazuh_pack(len(response)) + response)

        def handle(self):
            """Overriden handle method for TCP MITM server."""
            if self.server.mitm.handler_func is None:
                self.default_wazuh_handler()
            else:
                while not self.server.mitm.event.is_set():
                    received = self.recvall()
                    response = self.server.mitm.handler_func(received)
                    self.server.mitm.put_queue((received, response))
                    self.request.sendall(response)

    class DatagramHandler(socketserver.BaseRequestHandler):

        def unix_forward(self, data):
            """Default UDP unix socket forwarder for MITM servers."""
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as forwarded_sock:
                forwarded_sock.sendto(data, self.server.mitm.forwarded_socket_path)

        def default_wazuh_handler(self):
            """Default wazuh daemons UDP handler method for MITM server."""
            data = self.request[0]
            self.unix_forward(data)
            self.server.mitm.put_queue(data.rstrip(b'\x00'))

        def handle(self):
            """Overriden handle method for UDP MITM server."""
            if self.server.mitm.handler_func is None:
                self.default_wazuh_handler()
            else:
                data = self.request[0]
                self.server.mitm.handler_func(data)
                self.server.mitm.put_queue(data)

    class ManInTheMiddle:

        def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', func: callable = None):
            """Create a MITM server for the socket `socket_address`.

            Parameters
            ----------
            address : str or Tuple(str, int)
                Address of the socket, the format of the address depends on the type. A regular file path for AF_UNIX or
                a Tuple(HOST, PORT) for AF_INET
            family : str
                Family type of socket to connect to, AF_UNIX for unix sockets or AF_INET for port sockets.
                Default `'AF_UNIX'`
            connection_protocol : str
                It can be either 'TCP' or 'UDP'. Default `'TCP'`
            func : callable
                Function to be applied to every received data before sending it.
            """
            if isinstance(address, str) or (isinstance(address, tuple) and len(address) == 2
                                            and isinstance(address[0], str) and isinstance(address[1], int)):
                self.listener_socket_address = address
            else:
                raise TypeError(f"Invalid address type: {type(address)}. Valid types are str or Tuple(str, int)")

            if connection_protocol.lower() == 'tcp' or connection_protocol.lower() == 'udp':
                self.mode = connection_protocol.lower()
            else:
                raise TypeError(f'Invalid connection protocol detected: {connection_protocol.lower()}. '
                                f'Valid ones are TCP or UDP')

            if family == 'AF_UNIX' or family == 'AF_INET':
                self.family = family
            else:
                raise TypeError('Invalid family type detected. Valid ones are AF_UNIX or AF_INET')

            self.forwarded_socket_path = None

            class_tree = {
                'listener': {
                    'tcp': {
                        'AF_UNIX': StreamServerUnix,
                        'AF_INET': StreamServerPort
                    },
                    'udp': {
                        'AF_UNIX': DatagramServerUnix,
                        'AF_INET': DatagramServerPort
                    }
                },
                'handler': {
                    'tcp': StreamHandler,
                    'udp': DatagramHandler
                }
            }

            self.listener_class = class_tree['listener'][self.mode][self.family]
            self.handler_class = class_tree['handler'][self.mode]
            self.handler_func = func
            self.listener = None
            self.thread = None
            self.event = threading.Event()
            self._queue = Queue()

        def run(self, *args):
            """Run a MITM server."""
            # Rename socket if it is a file (AF_UNIX)
            if isinstance(self.listener_socket_address, str):
                self.forwarded_socket_path = f'{self.listener_socket_address}.original'
                os.rename(self.listener_socket_address, self.forwarded_socket_path)

            self.listener_class.allow_reuse_address = True
            self.listener = self.listener_class(self.listener_socket_address, self.handler_class)
            self.listener.mitm = self

            # Give proper permissions to socket
            if isinstance(self.listener_socket_address, str):
                uid = pwd.getpwnam('ossec').pw_uid
                gid = grp.getgrnam('ossec').gr_gid
                os.chown(self.listener_socket_address, uid, gid)
                os.chmod(self.listener_socket_address, 0o660)

            self.thread = threading.Thread(target=self.listener.serve_forever)
            self.thread.start()

        def start(self):
            self.run()

        def shutdown(self):
            """Gracefully shutdown a MITM server."""
            self.listener.shutdown()
            self.listener.socket.close()
            self.event.set()
            # Remove created unix socket and restore original
            if isinstance(self.listener_socket_address, str):
                os.remove(self.listener_socket_address)
                os.rename(self.forwarded_socket_path, self.listener_socket_address)

        @property
        def queue(self):
            return self._queue

        def put_queue(self, item):
            self._queue.put(item)
