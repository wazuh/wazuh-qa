# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
import zlib
from struct import pack
from wazuh_testing import logger

from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.monitoring import Queue


class Cipher:
    """Algorithm to perform encryption/decryption of manager-agent secure messages:
    https://documentation.wazuh.com/current/development/message-format.html#secure-message-format.
    """

    def __init__(self, data, key):
        self.block_size = 16
        self.data = data
        self.key_blowfish = key
        self.key_aes = key[:32]

    def encrypt_aes(self):
        iv = b'FEDCBA0987654321'
        cipher = AES.new(self.key_aes, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(self.data, self.block_size))

    def decrypt_aes(self):
        iv = b'FEDCBA0987654321'
        cipher = AES.new(self.key_aes, AES.MODE_CBC, iv)
        return cipher.decrypt(pad(self.data, self.block_size))

    def encrypt_blowfish(self):
        iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
        cipher = Blowfish.new(self.key_blowfish, Blowfish.MODE_CBC, iv)
        return cipher.encrypt(self.data)

    def decrypt_blowfish(self):
        iv = b'\xfe\xdc\xba\x98\x76\x54\x32\x10'
        cipher = Blowfish.new(self.key_blowfish, Blowfish.MODE_CBC, iv)
        return cipher.decrypt(self.data)


class RemotedSimulator:
    """Create an AF_INET server socket for simulating remoted connection.

    Args:
        server_address (str): Manager ip address.
        remoted_port (str): Remoted connection port.
        protocol (str): Remoted protocol.
        mode (str): Remoted mode (REJECT, DUMMY_ACK, CONTROLLED_ACK, WRONG_KEY, INVALID_MSG)
        client_keys (str): Client keys file path.
        start_on_init (boolean): Indicate if remoted simulator should start after initialization.
        rcv_msg_limit (int): max elements for the received message queue.
    """

    def __init__(self, server_address='127.0.0.1', remoted_port=1514, protocol='udp', mode='REJECT',
                 client_keys=WAZUH_PATH + '/etc/client.keys', start_on_init=True, rcv_msg_limit=0):
        self.protocol = protocol
        self.global_count = 1234567891
        self.local_count = 5555
        self.request_counter = 111
        self.request_confirmed = False
        self.request_answer = None
        self.keys = ({}, {})
        self.encryption_key = ""
        self.mode = mode
        self.server_address = server_address
        self.remoted_port = remoted_port
        self.client_keys_path = client_keys
        self.last_message_ctx = ""
        self.running = False
        self.upgrade_errors = False
        self.upgrade_success = False
        self.upgrade_notification = None
        self.wcom_message_version = None
        self.active_response_message = None
        self.listener_thread = None
        self.last_client = None
        self.rcv_msg_queue = Queue(rcv_msg_limit)

        self.change_default_listener = False
        if start_on_init:
            self.start()

    def start(self, custom_listener=None, args=[]):
        """Start socket and listener thread.

        Args:
            custom_listener (thread): Custom listener thread.
            args (list): Listener thread arguments.
        """
        if not self.running:
            self._start_socket()
            self.listener_thread = threading.Thread(target=(self.listener if not custom_listener else custom_listener),
                                                    args=args)
            self.listener_thread.setName('listener_thread')
            self.running = True
            self.listener_thread.start()

    def _start_socket(self):
        """Init remoted simulator socket."""
        if self.protocol == "tcp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.settimeout(10)
            self.sock.bind((self.server_address, self.remoted_port))
            self.sock.listen(1)
        elif self.protocol == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.settimeout(10)
            self.sock.bind((self.server_address, self.remoted_port))

    def set_wcom_message_version(self, version):
        """Set version for WPK tests.

        Args:
            version (str): WPK version.
        """
        self.wcom_message_version = version

    def set_active_response_message(self, ar_message):
        """Set message for AR tests.

        Args:
            ar_message (str): Active response message.
        """
        self.active_response_message = ar_message

    def stop(self):
        """Stop socket and listener thread"""
        if self.running:
            self.running = False
            self.listener_thread.join()
            self.sock.close()

    def create_encryption_key(self, agent_id, name, key):
        """Generate encryption key (using agent metadata and key).

        Args:
            agent_id (str): Agent id.
            name (str): Agent name.
            key (str): Encryption key.
        """
        sum1 = (hashlib.md5((hashlib.md5(name.encode()).hexdigest().encode() + hashlib.md5(
            agent_id.encode()).hexdigest().encode())).hexdigest().encode())[:15]
        sum2 = hashlib.md5(key.encode()).hexdigest().encode()
        self.encryption_key = sum2 + sum1

    def compose_sec_message(self, message, binary_data=None):
        """Compose event from raw message.

        Args:
            message (str): Raw message.
            binary_data (str): Binary data.
        """
        message = message.encode()
        if binary_data:
            message += binary_data
        random_number = b'55555'
        split = b':'
        global_counter = str(self.global_count).encode()
        local_counter = str(self.local_count).encode()

        msg = random_number + global_counter + split + local_counter + split + message
        msg_md5 = hashlib.md5(msg).hexdigest()
        sec_message = msg_md5.encode() + msg
        return sec_message

    def wazuh_padding(self, compressed_sec_message):
        """Add the Wazuh custom padding to each sec_message sent."""
        padding = 8
        extra = len(compressed_sec_message) % padding
        if extra > 0:
            padded_sec_message = (b'!' * (padding - extra)) + compressed_sec_message
        else:
            padded_sec_message = (b'!' * padding) + compressed_sec_message
        return padded_sec_message

    def encrypt(self, padded_sec_message, crypto_method):
        """Encrypt sec_message AES or Blowfish."""
        if crypto_method == "aes":
            encrypted_sec_message = Cipher(padded_sec_message, self.encryption_key).encrypt_aes()
        elif crypto_method == "blowfish":
            encrypted_sec_message = Cipher(padded_sec_message, self.encryption_key).encrypt_blowfish()
        return encrypted_sec_message

    def headers(self, encrypted_sec_message, crypto_method):
        """Add sec_message headers for AES or Blowfish Cyphers."""
        if crypto_method == "aes":
            header = "#AES:".encode()
        elif crypto_method == "blowfish":
            header = ":".encode()
        headers_sec_message = header + encrypted_sec_message
        return headers_sec_message

    def create_sec_message(self, message, crypto_method, binary_data=None):
        """Create a sec_message to Agent."""
        # Compose sec_message
        sec_message = self.compose_sec_message(message, binary_data)
        # Compress
        compressed_sec_message = zlib.compress(sec_message)
        # Padding
        padded_sec_message = self.wazuh_padding(compressed_sec_message)
        # Encrypt
        encrypted_sec_message = self.encrypt(padded_sec_message, crypto_method)
        # Add headers
        headers_sec_message = self.headers(encrypted_sec_message, crypto_method)
        return headers_sec_message

    def create_ack(self, crypto_method):
        """Create an ACK message."""
        return self.create_sec_message("#!-agent ack ", crypto_method)

    def build_new_com_message(self, command, payload=None):
        """Build com message with new format."""
        list_command = command.split(' ')
        message = None
        if list_command[0] == 'open':
            message = json.dumps({"command": list_command[0],
                                  "parameters": {
                                      "file": list_command[2],
                                      "mode": list_command[1]
                                  }})
        elif list_command[0] == 'write':
            payload_b64 = base64.b64encode(payload)
            payload_b64 = payload_b64.decode('ascii')
            message = json.dumps({"command": list_command[0],
                                  "parameters": {
                                      "file": list_command[2],
                                      "buffer": payload_b64,
                                      "length": (len(payload_b64) * 3) / 4 - payload_b64.count('=', -2)
                                  }})
        elif list_command[0] == 'close' or list_command[0] == 'sha1':
            message = json.dumps({"command": list_command[0],
                                  "parameters": {
                                      "file": list_command[1]
                                  }})
        elif list_command[0] == 'upgrade':
            message = json.dumps({"command": list_command[0],
                                  "parameters": {
                                      "file": list_command[1],
                                      "installer": list_command[2]
                                  }})
        else:
            pass
        return message

    def send_com_message(self, client_address, connection, command, payload=None, interruption_time=None):
        """
        Create a COM message

        Args:
            - client_address (str): Client of the connection.
            - connection (pair): Pair with manager connection attributes.
            - command (str): Pair connection and address.
            - payload (bin): Optional binary data to add to the message.
            - interruption_time (int): Time that will be added in between connections.
        """
        self.request_counter += 1
        if command == 'lock_restart -1' or self.wcom_message_version is None:
            message = self.create_sec_message(f"#!-req {self.request_counter} com {command}", 'aes',
                                              binary_data=payload)
        else:
            msg = self.build_new_com_message(command, payload=payload)
            message = self.create_sec_message(f"#!-req {self.request_counter} upgrade {msg}", 'aes', None)
        self.send(connection, message)

        if interruption_time:
            if connection:
                connection.close()
                self.sock.close()
                time.sleep(interruption_time)
                self._start_socket()
                connection, client_address = self.start_connection()
            else:
                time.sleep(interruption_time)

        self.request_confirmed = False

        timeout = time.time() + 60
        # Wait for confirmation
        while not self.request_confirmed:
            if time.time() > timeout:
                self.request_answer = 'Request confirmation never arrived'
                self.upgrade_errors = True
                raise TimeoutError(self.request_answer)
            data = self.receive_message(connection)
            ret = self.process_message(client_address, data)
            # Response -1 means connection have to be closed
            if ret == -1:
                time.sleep(0.1)
                connection.close()
                break
            # If there is a response, answer it
            elif ret:
                self.send(connection, ret)

        if command == 'lock_restart -1' or self.wcom_message_version is None:
            if not self.request_answer.startswith('ok '):
                self.upgrade_errors = True
                raise
        else:
            if f'"error":0' not in self.request_answer:
                self.upgrade_errors = True
                raise

        return self.request_answer

    def create_invalid(self):
        """Create an invalid message, without encryption and headers."""
        return "INVALID".encode()

    def update_counters(self):
        """Update message counters, used inside secure messages."""
        if self.local_count >= 9997:
            self.local_count = 0
            self.global_count = self.global_count + 1

        self.local_count = self.local_count + 1

    def decrypt_message(self, data, crypto_method):
        """Decrypt a message received from Agent."""
        if crypto_method == 'aes':
            msg_remove_header = bytes(data[5:])
            msg_decrypted = Cipher(msg_remove_header, self.encryption_key).decrypt_aes()
        else:
            msg_remove_header = bytes(data[1:])
            msg_decrypted = Cipher(msg_remove_header, self.encryption_key).decrypt_blowfish()

        padding = 0
        while msg_decrypted:
            if msg_decrypted[padding] == 33:
                padding += 1
            else:
                break
        msg_remove_padding = msg_decrypted[padding:]
        msg_decompress = zlib.decompress(msg_remove_padding)
        msg_decoded = msg_decompress.decode('ISO-8859-1')

        return msg_decoded

    def receive_message(self, connection):
        """Receive message from connection."""
        while True:
            if self.protocol == 'tcp':
                rcv = connection.recv(4)
                if len(rcv) == 4:
                    data_len = ((rcv[3] & 0xFF) << 24) | ((rcv[2] & 0xFF) << 16) | ((rcv[1] & 0xFF) << 8) | (
                                rcv[0] & 0xFF)

                    buffer_array = connection.recv(data_len)

                    if data_len == len(buffer_array):
                        return buffer_array
            else:
                buffer_array, client_address = self.sock.recvfrom(65536)
                return buffer_array

    def recv_all(self, connection, size: int):
        """Receive all messages until the limit size is reached.

        Args:
            connection (pair): Pair with manager connection attributes.
            size (int): Limit size of received messages.
        """

        buffer = bytearray()
        while len(buffer) < size:
            try:
                data = connection.recv(size - len(buffer))
                if not data:
                    break
                buffer.extend(data)
            except socket.timeout:
                continue
        return bytes(buffer)

    def listener(self):
        """Listener thread to read every received package from the socket and process it."""
        while self.running:
            if self.protocol == 'tcp':
                # Wait for a connection
                try:
                    connection, client_address = self.sock.accept()
                    self.last_client = connection
                    while self.running:
                        data = self.recv_all(connection, 4)
                        data_size = struct.unpack('<I', data[0:4])[0]
                        data = self.recv_all(connection, data_size)
                        try:
                            ret = self.process_message(client_address, data)
                        except Exception:
                            time.sleep(1)
                            connection.close()
                            self.last_client = None

                        # Response -1 means connection have to be closed
                        if ret == -1:
                            time.sleep(0.1)
                            connection.close()
                            self.last_client = None
                            break
                        # If there is a response, answer it
                        elif ret:
                            self.send(connection, ret)
                        else:
                            pass

                        # Active response message
                        if self.active_response_message:
                            msg = self.create_sec_message(f"#!-execd {self.active_response_message}", "aes")
                            self.active_response_message = None
                            self.send(connection, msg)
                except Exception:
                    continue

            elif self.protocol == 'udp':
                try:
                    data, client_address = self.sock.recvfrom(65536)
                    ret = self.process_message(client_address, data)
                    # If there is a response, answer it
                    if ret is not None and ret != -1:
                        self.send(client_address, ret)
                except socket.timeout:
                    continue

    def start_connection(self):
        """Established connection and receives startup message."""
        self.encryption_key = ""
        while not self.encryption_key and self.running:
            try:
                connection = None
                if self.protocol == 'tcp':
                    connection, client_address = self.sock.accept()
                else:
                    data, client_address = self.sock.recvfrom(65536)

                while not self.encryption_key and self.running:
                    # Receive ACK message and process it
                    if self.protocol == 'tcp':
                        data = self.receive_message(connection)
                    try:
                        ret = self.process_message(client_address, data)

                        # Response -1 means connection have to be closed
                        if ret == -1:
                            time.sleep(0.1)
                            connection.close()
                            break
                        # If there is a response, answer it
                        elif ret:
                            self.send(connection, ret)
                    except Exception:
                        time.sleep(1)
                        if connection:
                            connection.close()

                return connection, client_address
            except Exception:
                continue

    def upgrade_listener(self, filename, filepath, chunk_size, installer, sha1hash, simulate_interruption=False,
                         simulate_connection_error=False):
        """Listener thread that will finish when encryption_keys are obtained.

        Args:
            filename (str): Filename.
            filepath (str): File path
            chunk_size (int): Size of the chunk.
            installer (str): Name of the installer script.
            sha1hash (str): SHA1 has of specified file.
            simulate_interruption (boolean): Enable simulate connection interruption.
            simulate_connection_error (boolean): Enable simulate connection error.
        """
        self.upgrade_errors = False
        self.upgrade_success = False
        upgrade_socket_closed_timeout = 100

        while not self.upgrade_errors and self.running:
            try:
                connection, client_address = self.start_connection()

                time.sleep(60)
                self.send_com_message(client_address, connection, 'lock_restart -1')
                self.send_com_message(client_address, connection, f'open wb {filename}',
                                      interruption_time=5 if simulate_interruption else None)
                with open(filepath, 'rb') as f:
                    bytes_stream = f.read(chunk_size)
                    while len(bytes_stream) == chunk_size:
                        self.send_com_message(client_address, connection, f'write {len(bytes_stream)} {filename} ',
                                              payload=bytes_stream)
                        bytes_stream = f.read(chunk_size)
                    self.send_com_message(client_address, connection, f'write {len(bytes_stream)} {filename} ',
                                          payload=bytes_stream)

                self.send_com_message(client_address, connection, f'close {filename}')
                response = self.send_com_message(client_address, connection, f'sha1 {filename}')

                if self.wcom_message_version is None:
                    if response.split(' ')[1] != sha1hash:
                        self.upgrade_errors = True
                        raise
                elif f'"message":"{sha1hash}"' not in response:
                    self.upgrade_errors = True
                    raise

                self.send_com_message(client_address, connection, f'upgrade {filename} {installer}')
                self.upgrade_notification = None
                self.upgrade_success = True

                # Switch to common listener once the upgrade has ended
                if simulate_connection_error:
                    # Sleep long enough to make the connection after upgrade fail and generate a rollback
                    while not self.change_default_listener and upgrade_socket_closed_timeout > 0:
                        time.sleep(1)
                        upgrade_socket_closed_timeout -= 1

                    self.sock.close()
                    self._start_socket()
                return self.listener()
            except Exception:
                continue

    def send(self, dst, data):
        """Send method to write on the socket.

        Args:
            dst (socket): Address to write specified data.
            data (socket): Data to be send.
        """
        self.update_counters()
        if self.protocol == "tcp":
            try:
                length = pack('<I', len(data))
                dst.send(length + data)
            except:
                pass
        elif self.protocol == "udp":
            try:
                self.sock.sendto(data, dst)
            except:
                pass

    def process_message(self, source, received):
        """Process a received message and answer according to the simulator mode.

        Args:
            source (str): Source of the message.
            received (str): Received message.
        """

        # handle ping pong response
        if received == b'#ping':
            return b'#pong'

        # parse agent identifier and payload
        index = received.find(b'!')
        if index == 0:
            agent_identifier_type = "by_id"
            index = received[1:].find(b'!')
            agent_identifier = received[1:index + 1].decode()
            received = received[index + 2:]
        else:
            agent_identifier_type = "by_ip"
            agent_identifier = source[0]

        # parse crypto method
        if received.find(b'#AES') == 0:
            crypto_method = "aes"
        else:
            crypto_method = "blowfish"

        # Update keys to encrypt/decrypt
        self.update_keys()
        # TODO: Ask for specific keys depending on Agent Identifier
        keys = self.get_key()
        if keys is None:
            # No valid keys
            logger.error("Not valid keys used.")
            return -1
        (id, name, ip, key) = keys
        self.create_encryption_key(id, name, key)

        # Decrypt message
        rcv_msg = self.decrypt_message(received, crypto_method)

        ## Store message
        self.rcv_msg_queue.put(rcv_msg)

        # Hash message means a response is required
        if rcv_msg.find('#!-') != -1:
            req_index = rcv_msg.find('#!-req')
            if req_index != -1:
                if int(rcv_msg[req_index:].split(' ')[1]) == self.request_counter:
                    self.request_answer = ' '.join(rcv_msg[req_index:].split(' ')[2:])
                    self.request_confirmed = True
            hash_message = True
        else:
            hash_message = False

        if rcv_msg.find('upgrade_update_status') != -1:
            self.upgrade_notification = json.loads(rcv_msg[rcv_msg.find('\"parameters\":') + 13:-1])

        # Save context of received message for future asserts
        self.last_message_ctx = '{} {} {}'.format(agent_identifier_type, agent_identifier, crypto_method)

        # Create response
        if self.mode == "REJECT":
            return -1
        elif self.mode == "DUMMY_ACK":
            msg = self.create_ack(crypto_method)
        elif self.mode == "CONTROLLED_ACK":
            if hash_message:
                msg = self.create_ack(crypto_method)
            else:
                msg = None
        elif self.mode == "WRONG_KEY":
            self.create_encryption_key(id + 'inv', name + 'inv', key + 'inv')
            msg = self.create_ack(crypto_method)
        elif self.mode == "INVALID_MSG":
            msg = self.create_invalid()

        return msg

    def update_keys(self):
        """Update keys table with keys read from client.keys."""
        if not os.path.exists(self.client_keys_path):
            with open(self.client_keys_path, 'w+') as f:
                f.write("100 ubuntu-agent any TopSecret")

        with open(self.client_keys_path) as client_file:
            client_lines = client_file.read().splitlines()

            self.keys = ({}, {})
            for line in client_lines:
                (id, name, ip, key) = line.split(" ")
                self.keys[0][id] = (id, name, ip, key)
                self.keys[1][ip] = (id, name, ip, key)

    def get_key(self, key=None, dictionary="by_id"):
        """Get an specific key.

        Keys can be found in two dictionaries: by_id and by_ip. If no key is provided, the first item will be returned.

        Args:
            key (pair): Pair with by_id and by_ip key dictionaries.
            dictionary (str): Dictionary to used (by_id or by_ip)
        """
        try:
            if key is None:
                return next(iter(self.keys[0].values()))

            if dictionary == "by_ip":
                return self.keys[0][key]
            else:
                return self.keys[1][key]
        except:
            return None

    def set_mode(self, mode):
        """Set Remoted simulator work mode:

        Args:
            mode (str): Remoted simulator mode (REJECT,DUMMY_ACK, CONTROLLED_ACK, WRONG_KEY, INVALID_MSG).


            REJECT: Any connection will be rejected. UDP will ignore incoming connection, TCP will actively
            close incoming connection.
            DUMMY_ACK: Any received package will be answered with an ACK.
            CONTROLLED_ACK: Received package will be processed and decrypted. Only valid decrypted messages.
            starting with #!- will receive an ACK
            WRONG_KEY: Any received package will be answered with an ACK created with incorrect keys.
            INVALID_MSG: Any received package will be answered with a message that is not encrypted and without header.
        """
        self.mode = mode

    def wait_upgrade_process(self, timeout=None):
        """Wait for upgrade process to run.

        Args:
            timeout (int): Max timeout in seconds.

        Returns:
            Boolean: Upgrade success message.
            String: Request answer.
        """
        while not self.upgrade_success and not self.upgrade_errors and (timeout is None or timeout > 0):
            time.sleep(1)
            if timeout is not None:
                timeout -= 1
        return self.upgrade_success, self.request_answer

    def wait_upgrade_notification(self, timeout=None):
        """Wait for the arrival of the agent notification.

        Args:
            timeout (int): Max timeout in seconds.

        Returns:
            string: Upgrade notification.
        """
        while (self.upgrade_notification is None) and (timeout is None or timeout > 0):
            time.sleep(1)
            if timeout is not None:
                timeout -= 1
        return self.upgrade_notification

    def request(self, message):
        """Send request to agent using current request counter.

        Args:
            message (str): Request content.
        """
        if self.last_client:
            request = self.create_sec_message(f'#!-req {self.request_counter} {message}', 'aes')
            self.send(self.last_client, request)
