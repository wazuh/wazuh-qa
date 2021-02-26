#!/usr/bin/python
# Wazuh agents load simulator
# Copyright (C) 2015-2021, Wazuh Inc.
# January 28, 2020.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Python 3.7 or greater
# Dependencies: pip3 install pycryptodome

import hashlib
import json
import os
import socket
import ssl
import threading
import zlib
import logging
from random import randint, sample, choice
from stat import S_IFLNK, S_IFREG, S_IRWXU, S_IRWXG, S_IRWXO
from string import ascii_letters, digits
from struct import pack
from time import mktime, localtime, sleep, time
from wazuh_testing.tools.remoted_sim import Cipher


_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')

os_list = ["debian7", "debian8", "debian9", "debian10", "ubuntu12.04",
           "ubuntu14.04", "ubuntu16.04", "ubuntu18.04", "mojave"]
agent_count = 1


class Agent:
    """ Class that allows us to simulate an agent registered in a manager.

    This simulated agent also allows sending-receiving messages and commands, in addition to simulating the
    syscollector, FIM and rootcheck modules by making use of other classes such as Inventory, Rootcheck, GeneratorFIM
    and GeneratorIntegrityFIM.

    Args:
        manager_address (str): Manager IP address.
        cypher (str, optional): Cypher method. It can be [aes, blowfish]. Default aes.
        os (str, optional): Agent operating system. Default None for choosing randomly.
        inventory_sample (str, optional): File where are sample inventory messages.
        rootcheck_sample (str, optional): File where are sample rootcheck messages.
        id (str, optional): ID of the agent. Specify only if it already exists.
        name (str, optional): Agent name. Specify only if it already exists.
        key (str, optional): Client key. Specify only if it already exists.
        version (str, optional): Wazuh agent version. Default v3.12.0.
        fim_eps (int, optional): Set the maximum event reporting throughput. Events are messages that will produce an
                                 alert.
        fim_integrity_eps (int, optional): Set the maximum database synchronization message throughput.
        authd_password (str), optional: Password for registration if needed.

    Attributes:
        id (str): ID of the agent.
        name (str): Agent name.
        key (str): Agent key. Used for creating an encryption_key.
        long_version (str): Agent version in format x.y.z
        short_version (str): Agent version in format x.y
        cypher (str): Encryption method for message communication.
        os (str): Agent operating system.
        fim_eps (int): Set the maximum event reporting throughput. Events are messages that will produce an alert.
        fim_integrity_eps (int): Set the maximum database synchronization message throughput.
        manager_address (str): Manager IP address.
        encryption_key (bytes): Encryption key used for encrypt and decrypt the message.
        keep_alive_msg (bytes): Keep alive event (read from template data according to OS and parsed to an event).
        startup_msg (bytes): Startup event sent before the first keep alive event.
        authd_password (str): Password for manager registration.
        inventory_sample (str): File where are sample inventory messages.
        rootcheck_sample (str): File where are sample rootcheck messages.
        inventory (Inventory): Object to simulate syscollector message events.
        rootcheck (Rootcheck): Object to simulate rootcheck message events.
        fim (GeneratorFIM): Object to simulate FIM message events.
        fim_integrity (GeneratorIntegrityFIM): Object to simulate FIM integrity message events.
        modules (dict): Agent modules with their associated configuration info.
        sha_key (str): Shared key between manager and agent for remote upgrading.
        upgrade_exec_result (int): Upgrade result status code.
        send_upgrade_notification (boolean): If True, it will be sent the upgrade status message after "upgrading".
        upgrade_script_result (int): Variable to mock the upgrade script result. Used for simulating a remote upgrade.
        stop_receive (int): Flag to determine when to activate and deactivate the agent event listener.
        stage_disconnect (str): WPK process state variable.
        debug (boolean): enable debug logging level.
    """
    def __init__(self, manager_address, cypher="aes", os=None, inventory_sample=None, rootcheck_sample=None,
                 id=None, name=None, key=None, version="v3.12.0", fim_eps=None, fim_integrity_eps=None,
                 authd_password=None):
        self.id = id
        self.name = name
        self.key = key
        if version is not None:
            self.long_version = version
            ver_split = version.replace("v", "").split(".")
            self.short_version = f"{'.'.join(ver_split[:2])}"
        self.cypher = cypher
        self.os = os
        self.fim_eps = 1000 if fim_eps is None else fim_eps
        self.fim_integrity_eps = 10 if fim_integrity_eps is None \
            else fim_integrity_eps
        self.manager_address = manager_address
        self.encryption_key = ""
        self.keep_alive_msg = ""
        self.startup_msg = ""
        self.authd_password = authd_password
        self.inventory_sample = inventory_sample
        self.inventory = None
        self.rootcheck_sample = rootcheck_sample
        self.rootcheck = None
        self.fim = None
        self.fim_integrity = None
        self.modules = {
            "keepalive": {"status": "enabled", "frequency": 10.0},
            "fim": {"status": "enabled", "eps": self.fim_eps},
            "fim_integrity": {"status": "disabled", "eps": self.fim_integrity_eps},
            "syscollector": {"status": "disabled", "frequency": 60.0, "eps": 200},
            "rootcheck": {"status": "enabled", "frequency": 60.0, "eps": 200},
            "receive_messages": {"status": "enabled"},
        }
        self.sha_key = None
        self.upgrade_exec_result = None
        self.send_upgrade_notification = False
        self.upgrade_script_result = 0
        self.stop_receive = 0
        self.stage_disconnect = None
        self.setup()

    def setup(self):
        """Set up agent: os, registration, encryption key, start up msg and activate modules."""
        self.set_os()

        if self.id is None and self.name is None and self.key is None:
            self.set_name()
            self.register()
        elif any([self.id, self.name, self.key]) and not all([self.id, self.name, self.key]):
            raise ValueError("All the parameters [id, name, key] have to be specified together")

        self.create_encryption_key()
        self.create_keep_alive()
        self.create_hc_startup()
        self.initialize_modules()

    def set_os(self):
        """Pick random OS from a custom os list."""
        if self.os is None:
            self.os = os_list[agent_count % len(os_list) - 1]

    def set_wpk_variables(self, sha=None, upgrade_exec_result=None, upgrade_notification=False, upgrade_script_result=0,
                          stage_disconnect=None):
        """Set variables related to wpk simulated responses.

        Args:
            sha (str): Shared key between manager and agent for remote upgrading.
            upgrade_exec_result (int): Upgrade result status code.
            upgrade_notification (boolean): If True, it will be sent the upgrade status message after "upgrading".
            upgrade_script_result (int): Variable to mock the upgrade script result. Used for simulating a remote
                                         upgrade.
            stage_disconnect (str): WPK process state variable.
        """
        self.sha_key = sha
        self.upgrade_exec_result = upgrade_exec_result
        self.send_upgrade_notification = upgrade_notification
        self.upgrade_script_result = upgrade_script_result
        self.stage_disconnect = stage_disconnect

    def set_name(self):
        """Set a random agent name."""
        random_string = ''.join(sample('0123456789abcdef' * 2, 8))
        if self.inventory_sample is None:
            self.name = "{}-{}-{}".format(agent_count, random_string, self.os)
        else:
            inventory_string = self.inventory_sample.replace(".", "")
            self.name = "{}-{}-{}-{}".format(agent_count,
                                             random_string, self.os,
                                             inventory_string)

    def register(self):
        """Request to register the agent in the manager.

        In addition, it sets the agent id and agent key with the response data.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssl_socket = context.wrap_socket(sock,
                                         server_hostname=self.manager_address)
        ssl_socket.connect((self.manager_address, 1515))
        if self.authd_password is None:
            event = "OSSEC A:'{}'\n".format(self.name).encode()
        else:
            event = "OSSEC PASS: {} OSSEC A:'{}'\n".format(self.authd_password,
                                                           self.name).encode()
        ssl_socket.send(event)
        recv = ssl_socket.recv(4096)
        registration_info = recv.decode().split("'")[1].split(" ")
        self.id = registration_info[0]
        self.key = registration_info[3]
        ssl_socket.close()
        sock.close()
        logging.debug("Registration - {}({})".format(self.name, self.id))

    @staticmethod
    def wazuh_padding(compressed_event):
        """Add the Wazuh custom padding to each event sent.

        Args:
            compressed_event (bytes): Compressed event with zlib.

        Returns:
            bytes: Padded event.

        Examples:
            >>> wazuh_padding(b'x\\x9c\\x15\\xc7\\xc9\\r\\x00 \\x08\\x04\\xc0\\x96\\\\\\x94\\xcbn0H\\x03\\xda\\x7f
                               \\x8c\\xf3\\x1b\\xd9e\\xec\\nJ[\\x04N\\xcf\\xa8\\xa6\\xa8\\x12\\x8d\\x08!\\xfe@}\\xb0
                               \\xa89\\xe6\\xef\\xbc\\xfb\\xdc\\x07\\xb7E\\x0f\\x1b)
                b'!!!!!!!!x\\x9c\\x15\\xc7\\xc9\\r\\x00 \\x08\\x04\\xc0\\x96\\\\\\x94\\xcbn0H\\x03\\xda\\x7f\\x8c\\xf3
                \\x1b\\xd9e\\xec\\nJ[\\x04N\\xcf\\xa8\\xa6\\xa8\\x12\\x8d\\x08!\\xfe@}\\xb0\\xa89\\xe6\\xef\\xbc\\xfb
                \\xdc\\x07\\xb7E\\x0f\\x1b'
        """
        padding = 8
        extra = len(compressed_event) % padding
        if extra > 0:
            padded_event = (b'!' * (padding - extra)) + compressed_event
        else:
            padded_event = (b'!' * padding) + compressed_event
        return padded_event

    def create_encryption_key(self):
        """Generate encryption key (using agent metadata and key)."""
        agent_id = self.id.encode()
        name = self.name.encode()
        key = self.key.encode()
        sum1 = (hashlib.md5((hashlib.md5(name).hexdigest().encode()
                             + hashlib.md5(agent_id).hexdigest().encode())).hexdigest().encode())
        sum1 = sum1[:15]
        sum2 = hashlib.md5(key).hexdigest().encode()
        key = sum2 + sum1
        self.encryption_key = key

    @staticmethod
    def compose_event(message):
        """Compose event from raw message.

        Returns:
            bytes: Composed event.

        Examples:
            >>> compose_event('test')
            b'6ef859712d8b215d9daf071ff67aaa62555551234567891:5555:test'
        """
        message = message.encode()
        random_number = b'55555'
        global_counter = b'1234567891'
        split = b':'
        local_counter = b'5555'
        msg = random_number + global_counter + split + local_counter + split + message
        msg_md5 = hashlib.md5(msg).hexdigest()
        event = msg_md5.encode() + msg
        return event

    def encrypt(self, padded_event):
        """Encrypt event using AES or Blowfish encryption.

        Args:
            padded_event (bytes): Padded event.

        Returns:
            bytes: Encrypted event.

        Examples:
            >>> agent.encrypt(b'!!!!!!!!x\\x9c\\x15\\xc7\\xc9\\r\\x00 \\x08\\x04\\xc0\\x96\\\\\\x94\\xcbn0H\\x03\\xda
                               \\x7f\\x8c\\xf3\\x1b\\xd9e\\xec\\nJ[\\x04N\\xcf\\xa8\\xa6\\xa8\\x12\\x8d\\x08!\\xfe@}
                               \\xb0\\xa89\\xe6\\xef\\xbc\\xfb\\xdc\\x07\\xb7E\\x0f\\x1b')
                b"\\xf8\\x8af[\\xfc'\\xf6j&1\\xd5\\xe1t|\\x810\\xe70G\\xe3\\xbc\\x8a\\xdbV\\x94y\\xa3A\\xb5q\\xf7
                \\xb52<\\x9d\\xc8\\x83=o1U\\x1a\\xb3\\xf1\\xf5\\xde\\xe0\\x8bV\\xe99\\x9ej}#\\xf1\\x99V\\x12NP^T
                \\xa0\\rYs\\xa2n\\xe8\\xa5\\xb1\\r[<V\\x16%q\\xfc"
        """
        encrypted_event = None
        if self.cypher == "aes":
            encrypted_event = Cipher(padded_event, self.encryption_key).encrypt_aes()
        if self.cypher == "blowfish":
            encrypted_event = Cipher(padded_event, self.encryption_key).encrypt_blowfish()
        return encrypted_event

    def headers(self, agent_id, encrypted_event):
        """
        Add event headers for AES or Blowfish Cyphers.

        Args:
            agent_id (str): Agent id.
            encrypted_event (str): Encrypted event.

        Returns:
            bytes: Encrypted event with headers.
        """
        header = None
        if self.cypher == "aes":
            header = "!{0}!#AES:".format(agent_id).encode()
        if self.cypher == "blowfish":
            header = "!{0}!:".format(agent_id).encode()
        return header + encrypted_event

    def create_event(self, message):
        """Build an event from a raw string message.

        Args:
            message (str): Raw message.

        Returns:
            bytes: Built event (compressed, padded, enceypted and with headers).

        Examples:
            >>> create_event('test message')
            b'!005!#AES:\\xab\\xfa\\xcc2;\\x87\\xab\\x7fUH\\x03>_J\\xda=I\\x96\\xb5\\xa4\\x89\\xbe\\xbf`\\xd0\\xad
            \\x03\\x06\\x1aN\\x86 \\xc2\\x98\\x93U\\xcc\\xf5\\xe3@%\\xabS!\\xd3\\x9d!\\xea\\xabR\\xf9\\xd3\\x0b\\
            xcc\\xe8Y\\xe31*c\\x17g\\xa6M\\x0b&\\xc0>\\xc64\\x815\\xae\\xb8[bg\\xe3\\x83\\x0e'
        """
        # Compose event
        event = self.compose_event(message)
        # Compress
        compressed_event = zlib.compress(event)
        # Padding
        padded_event = self.wazuh_padding(compressed_event)
        # Encrypt
        encrypted_event = self.encrypt(padded_event)
        # Add headers
        headers_event = self.headers(self.id, encrypted_event)

        return headers_event

    def receive_message(self, sender):
        """Agent listener to receive messages and process the accepted commands.

        Args:
            sender (Sender): Object to establish connection with the manager socket and receive/send information.
        """
        while self.stop_receive == 0:
            if sender.protocol == 'tcp':
                rcv = sender.socket.recv(4)
                if len(rcv) == 4:
                    data_len = int.from_bytes(rcv, 'little')
                    try:
                        buffer_array = sender.socket.recv(data_len)
                    except MemoryError:
                        logging.critical(f"Memory error, trying to allocate {data_len}")
                        return

                    if data_len != len(buffer_array):
                        continue
                else:
                    continue
            else:
                buffer_array, client_address = sender.socket.recvfrom(65536)
            index = buffer_array.find(b'!')
            if index == 0:
                index = buffer_array[1:].find(b'!')
                buffer_array = buffer_array[index + 2:]
            if self.cypher == "aes":
                msg_remove_header = bytes(buffer_array[5:])
                msg_decrypted = Cipher(msg_remove_header, self.encryption_key).decrypt_aes()
            else:
                msg_remove_header = bytes(buffer_array[1:])
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
            self.process_message(sender, msg_decoded)

    def stop_receiver(self):
        """Stop Agent listener."""
        self.stop_receive = 1

    def process_message(self, sender, message):
        """Process agent received messages.

        If the message contains reserved words, then it will be proceed as command.

        Args:
            sender (Sender): Object to establish connection with the manager socket and receive/send information.
            message (str): Decoder message in ISO-8859-1 format.
        """
        msg_decoded_list = message.split(' ')
        if '#!-req' in msg_decoded_list[0]:
            self.process_command(sender, msg_decoded_list)

    def process_command(self, sender, message_list):
        """Process agent received commands through the socket.

        Args:
            sender (Sender): Object to establish connection with the manager socket and receive/send information.
            message_list (list): Message splitted by white spaces.

        Raises:
            ValueError: if 'sha1' command and sha_key Agent value is not defined.
            ValueError: if execution result is not configured in the Agent.
            ValueError: if command is not recognized.
        """

        req_code = message_list[1]

        if 'com' in message_list:
            """ Examples:
            ['12d95abf04334f90f8dc3140031b3e7b342680000000130:5489:#!-req', '81d15486', 'com', 'close',
                'wazuh_agent_v4.2.0_linux_x86_64.wpk']
            ['dff5324c331a37d56978f7f034f2634e599120000000130:5490:#!-req', '81d15487', 'com', 'sha1',
                'wazuh_agent_v4.2.0_linux_x86_64.wpk']
            ['8c0e7a8d75fea76016040ce436f9fb41193290000000130:5491:#!-req', '81d15488', 'com', 'upgrade',
                'wazuh_agent_v4.2.0_linux_x86_64.wpk', 'upgrade.sh']
            """
            com_index = message_list.index('com')
            command = message_list[com_index + 1]

        elif 'upgrade' in message_list:
            """ Examples:
            ['5e085e566814750136f3926f758349cb232030000000130:5492:#!-req', '81d15489', 'upgrade',
                '{"command":"clear_upgrade_result","parameters":{}}']
            """
            com_index = message_list.index('upgrade')
            json_command = json.loads(message_list[com_index + 1])
            command = json_command['command']
        elif 'getconfig' in message_list:
            """ Examples:
            ['ececac937b8e5dead15e9096e8bd5215214970000000002:3090:#!-req', 'c2b2c9e3', 'agent', 'getconfig', 'client']
            """
            command = 'getconfig'
        elif 'getstate' in message_list:
            """ Examples:
            ['ececac937b8e5dead15e9096e8bd5215214970000000002:3090:#!-req', 'c2b2c9e3', 'logcollector', 'getstate']
            """
            command = 'getstate'
        else:
            return

        logging.debug(f"Processing command: {message_list}")

        if command in ['lock_restart', 'open', 'write', 'close','clear_upgrade_result']:
            if command == 'lock_restart' and self.stage_disconnect == 'lock_restart':
                self.stop_receive = 1
            elif command == 'open' and self.stage_disconnect == 'open':
                self.stop_receive = 1
            elif command == 'write' and self.stage_disconnect == 'write':
                self.stop_receive = 1
            elif command == 'close' and self.stage_disconnect == 'close':
                self.stop_receive = 1
            elif command == 'clear_upgrade_result' and self.stage_disconnect == 'clear_upgrade_result':
                self.stop_receive = 1
            else:
                if self.short_version < "4.1" or command == 'lock_restart':
                    sender.send_event(self.create_event(f'#!-req {message_list[1]} ok '))
                else:
                    sender.send_event(self.create_event(f'#!-req {message_list[1]} '
                                                        f'{{"error":0, "message":"ok", "data":[]}} '))
        elif command == 'getconfig':
            response_json = '{"client":{"config-profile":"centos8","notify_time":10,"time-reconnect":60}}'
            sender.send_event(self.create_event(f'#!-req {req_code} ok {response_json}'))
        elif command == 'getstate':
            response_json = '{"error":0,"data":{"global":{"start":"2021-02-26, 06:41:26","end":"2021-02-26 08:49:19"}}}'
            sender.send_event(self.create_event(f'#!-req {req_code} ok {response_json}'))
        elif command == 'sha1':
            # !-req num ok {sha}
            if self.sha_key:
                if command == 'sha1' and self.stage_disconnect == 'sha1':
                    self.stop_receive = 1
                else:
                    if self.short_version < "4.1":
                        sender.send_event(self.create_event(f'#!-req {message_list[1]} '
                                                            f'ok {self.sha_key}'))
                    else:
                        sender.send_event(self.create_event(f'#!-req {message_list[1]} {{"error":0, '
                                                            f'"message":"{self.sha_key}", "data":[]}}'))
            else:
                raise ValueError(f'WPK SHA key should be configured in agent')

        elif command == 'upgrade':
            if self.upgrade_exec_result:
                if command == 'upgrade' and self.stage_disconnect == 'upgrade':
                    self.stop_receive = 1
                else:
                    if self.short_version < "4.1":
                        sender.send_event(self.create_event(f'#!-req {message_list[1]} ok {self.upgrade_exec_result}'))
                    else:
                        sender.send_event(self.create_event(f'#!-req {message_list[1]} {{"error":0, '
                                                            f'"message":"{self.upgrade_exec_result}", "data":[]}}'))
                    if self.send_upgrade_notification:
                        message = 'Upgrade was successful' if self.upgrade_script_result == 0 else 'Upgrade failed'
                        status = 'Done' if self.upgrade_script_result == 0 else 'Failed'
                        upgrade_update_status_message = {
                            'command': 'upgrade_update_status',
                            'parameters': {
                                'error': self.upgrade_script_result,
                                'message': message,
                                'status': status,
                            }
                        }
                        sender.send_event(self.create_event("u:upgrade_module:" +
                                                            json.dumps(upgrade_update_status_message)))
            else:
                raise ValueError(f'Execution result should be configured in agent')
        else:
            raise ValueError(f'Unrecognized command {command}')

    def create_hc_startup(self):
        """Set the agent startup event."""
        msg = "#!-agent startup "
        self.startup_msg = self.create_event(msg)

    def create_keep_alive(self):
        """Set the keep alive event from keepalives operating systemd data."""
        with open(os.path.join(_data_path, 'keepalives.txt'), 'r') as fp:
            line = fp.readline()
            while line:
                if line.strip("\n") == self.os:
                    msg = fp.readline()
                    line = fp.readline()
                    while line and line.strip("\n") not in os_list:
                        msg = msg + line
                        line = fp.readline()
                    break
                line = fp.readline()
        msg = msg.replace("<VERSION>", self.long_version)
        self.keep_alive_msg = self.create_event(msg)

    def initialize_modules(self):
        """Initialize and enable agent modules."""
        if self.modules["syscollector"]["status"] == "enabled":
            self.inventory = Inventory(self.os, self.inventory_sample)
        if self.modules["rootcheck"]["status"] == "enabled":
            self.rootcheck = Rootcheck(self.rootcheck_sample)
        if self.modules["fim"]["status"] == "enabled":
            self.fim = GeneratorFIM(self.id, self.name, self.short_version)
        if self.modules["fim_integrity"]["status"] == "enabled":
            self.fim_integrity = GeneratorIntegrityFIM(self.id, self.name, self.short_version)

    def get_connection_status(self):
        numeric_id = int(self.id)
        connection_status_query = f'select connection_status from agent where id={numeric_id} limit 1'
        result = wdb.get_query_result(connection_status_query)
        if type(result) is list and len(result) > 0:
            result = result[0]
        else:
            result = "Not in global.db"
        return result

    def wait_status_active(self):
        check_status_retries = 10
        while check_status_retries > 0:
            check_status_retries -= 1
            status = self.get_connection_status()
            if status == 'active':
                return
            logging.warning(f"Retrying: {check_status_retries}, {status}")
            sleep(10)
        logging.error(f"Waiting for status active aborted. Max retries reached.")


class Inventory:
    def __init__(self, os, inventory_sample=None):
        self.os = os
        self.SYSCOLLECTOR = 'syscollector'
        self.SYSCOLLECTOR_MQ = 'd'
        self.inventory = []
        self.inventory_path = ""
        self.inventory_sample = inventory_sample
        self.setup()

    def setup(self):
        if self.inventory_sample is None:
            inventory_files = os.listdir(f"inventory/{self.os}")
            self.inventory_path = f"inventory/{self.os}/{choice(inventory_files)}"
        else:
            self.inventory_path = f"inventory/{self.os}/{self.inventory_sample}"
        with open(self.inventory_path) as fp:
            line = fp.readline()
            while line:
                if not line.startswith("#"):
                    msg = "{0}:{1}:{2}".format(self.SYSCOLLECTOR_MQ, self.SYSCOLLECTOR, line.strip("\n"))
                    self.inventory.append(msg)
                line = fp.readline()


class Rootcheck:
    def __init__(self, os, rootcheck_sample=None):
        self.os = os
        self.ROOTCHECK = 'rootcheck'
        self.ROOTCHECK_MQ = '9'
        self.rootcheck = []
        self.rootcheck_path = ""
        self.rootcheck_sample = rootcheck_sample
        self.setup()

    def setup(self):
        if self.rootcheck_sample is None:
            self.rootcheck_path = os.path.join(_data_path, 'rootcheck.txt')
        else:
            self.rootcheck_path = os.path.join(_data_path, self.rootcheck_sample)
        with open(self.rootcheck_path) as fp:
            line = fp.readline()
            while line:
                if not line.startswith("#"):
                    msg = "{0}:{1}:{2}".format(self.ROOTCHECK_MQ, self.ROOTCHECK, line.strip("\n"))
                    self.rootcheck.append(msg)
                line = fp.readline()


class GeneratorIntegrityFIM:
    def __init__(self, agent_id, agent_name, agent_version):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.INTEGRITY_MQ = "5"
        self.event_type = None
        self.fim_generator = GeneratorFIM(self.agent_id, self.agent_name, self.agent_version)

    def format_message(self, message):
        return '{0}:[{1}] ({2}) any->syscheck:{3}'.format(self.INTEGRITY_MQ, self.agent_id, self.agent_name, message)

    def generate_message(self):
        data = None
        if self.event_type in ["integrity_check_global", "integrity_check_left", "integrity_check_right"]:
            id = int(time())
            data = {"id": id,
                    "begin": self.fim_generator.random_file(),
                    "end": self.fim_generator.random_file(),
                    "checksum": self.fim_generator.random_sha1()}

        if self.event_type == "integrity_clear":
            id = int(time())
            data = {"id": id}

        if self.event_type == "state":
            timestamp = int(time())
            self.fim_generator.generate_attributes()
            attributes = self.fim_generator.get_attributes()
            data = {"path": self.fim_generator._file,
                    "timestamp": timestamp,
                    "attributes": attributes}

        message = json.dumps({"component": "syscheck", "type": self.event_type, "data": data})
        return self.format_message(message)

    def get_message(self, event_type=None):
        if event_type is not None:
            self.event_type = event_type
        else:
            self.event_type = choice(["integrity_check_global", "integrity_check_left", "integrity_check_right",
                                      "integrity_clear", "state"])

        return self.generate_message()


class GeneratorFIM:
    def __init__(self, agent_id, agent_name, agent_version):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.FILE_ROOT = '/root/'
        self._file = self.FILE_ROOT + 'a'
        self._size = 0
        self._mode = S_IFREG | S_IRWXU
        self._uid = 0
        self._gid = 0
        self._md5 = 'xxx'
        self._sha1 = 'xxx'
        self._sha256 = 'xxx'
        self._uname = 'root'
        self._gname = 'root'
        self._mdate = int(mktime(localtime()))
        self._permissions = "rw-r--r--"
        self._inode = 0
        self._checksum = "f65b9f66c5ef257a7566b98e862732640d502b6f"
        self.SYSCHECK = 'syscheck'
        self.SYSCHECK_MQ = 8
        self.DEFAULT_FILE_LENGTH = 10
        self.MAX_SIZE = 1024
        self.USERS = {0: 'root', 1000: 'Dave', 1001: 'Connie'}
        self.MAX_TIMEDIFF = 3600
        self.MAX_INODE = 1024
        self.baseline_completed = 0
        self.event_mode = None
        self.event_type = None

    def random_file(self):
        self._file = self.FILE_ROOT + ''.join(sample(ascii_letters + digits, self.DEFAULT_FILE_LENGTH))
        return self._file

    def random_size(self):
        self._size = randint(-1, self.MAX_SIZE)
        return self._size

    def random_mode(self):
        self._mode = choice((S_IFREG, S_IFLNK))

        if self._mode == S_IFLNK:
            self._mode |= S_IRWXU | S_IRWXG | S_IRWXO
            self._md5 = 'xxx'
            self._sha1 = 'xxx'
        else:
            s = sample((S_IRWXU, S_IRWXG, S_IRWXO), 2)
            self._mode |= s[0] | s[1]

        return self._mode

    def random_uid(self):
        self._uid = choice(list(self.USERS.keys()))
        self._uname = self.USERS[self._uid]
        return self._uid, self._uname

    def random_gid(self):
        self._gid = choice(list(self.USERS.keys()))
        self._gname = self.USERS[self._gid]
        return self._gid, self._gname

    def random_md5(self):
        if self._mode & S_IFREG == S_IFREG:
            self._md5 = ''.join(sample('0123456789abcdef' * 2, 32))

        return self._md5

    def random_sha1(self):
        if self._mode & S_IFREG == S_IFREG:
            self._sha1 = ''.join(sample('0123456789abcdef' * 3, 40))

        return self._sha1

    def random_sha256(self):
        if self._mode & S_IFREG == S_IFREG:
            self._sha256 = ''.join(sample('0123456789abcdef' * 4, 64))

        return self._sha256

    def random_time(self):
        self._mdate += randint(1, self.MAX_TIMEDIFF)
        return self._mdate

    def random_inode(self):
        self._inode = randint(1, self.MAX_INODE)
        return self._inode

    def generate_attributes(self):
        self.random_file()
        self.random_size()
        self.random_mode()
        self.random_uid()
        self.random_gid()
        self.random_md5()
        self.random_sha1()
        self.random_sha256()
        self.random_time()
        self.random_inode()

    def check_changed_attributes(self, attributes, old_attributes):
        changed_attributes = []
        if attributes["size"] != old_attributes["size"]:
            changed_attributes.append("size")
        if attributes["perm"] != old_attributes["perm"]:
            changed_attributes.append("permission")
        if attributes["uid"] != old_attributes["uid"]:
            changed_attributes.append("uid")
        if attributes["gid"] != old_attributes["gid"]:
            changed_attributes.append("gid")
        if attributes["user_name"] != old_attributes["user_name"]:
            changed_attributes.append("user_name")
        if attributes["group_name"] != old_attributes["group_name"]:
            changed_attributes.append("group_name")
        if attributes["inode"] != old_attributes["inode"]:
            changed_attributes.append("inode")
        if attributes["mtime"] != old_attributes["mtime"]:
            changed_attributes.append("mtime")
        if attributes["hash_md5"] != old_attributes["hash_md5"]:
            changed_attributes.append("md5")
        if attributes["hash_sha1"] != old_attributes["hash_sha1"]:
            changed_attributes.append("sha1")
        if attributes["hash_sha256"] != old_attributes["hash_sha256"]:
            changed_attributes.append("sha256")

        return changed_attributes

    def get_attributes(self):
        attributes = {
            "type": "file", "size": self._size,
            "perm": self._permissions, "uid": str(self._uid),
            "gid": str(self._gid), "user_name": self._uname,
            "group_name": self._gname, "inode": self._inode,
            "mtime": self._mdate, "hash_md5": self._md5,
            "hash_sha1": self._sha1, "hash_sha256": self._sha256,
            "checksum": self._checksum
        }
        return attributes

    def format_message(self, message):
        if self.agent_version >= "3.12":
            return '{0}:[{1}] ({2}) any->syscheck:{3}' \
                .format(self.SYSCHECK_MQ, self.agent_id,
                        self.agent_name, message)
        else:
            # If first time generating. Send control message to simulate
            # end of FIM baseline.
            if self.baseline_completed == 0:
                self.baseline_completed = 1
                return '{0}:{1}:{2}'.format(self.SYSCHECK_MQ, self.SYSCHECK,
                                            "syscheck-db-completed")
            return '{0}:{1}:{2}'.format(self.SYSCHECK_MQ, self.SYSCHECK,
                                        message)

    def generate_message(self):
        if self.agent_version >= "3.12":
            if self.event_type == "added":
                timestamp = int(time())
                self.generate_attributes()
                attributes = self.get_attributes()
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes}
            elif self.event_type == "modified":
                timestamp = int(time())
                self.generate_attributes()
                attributes = self.get_attributes()
                self.generate_attributes()
                old_attributes = self.get_attributes()
                changed_attributes = self.check_changed_attributes(attributes, old_attributes)
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes,
                        "old_attributes": old_attributes,
                        "changed_attributes": changed_attributes}
            else:
                timestamp = int(time())
                self.generate_attributes()
                attributes = self.get_attributes()
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes}

            message = json.dumps({"type": "event", "data": data})

        else:
            self.generate_attributes()
            message = f'{self._size}:{self._mode}:{self._uid}:{self._gid}:{self._md5}:{self._sha1}:{self._uname}:' \
                      f'{self._gname}:{self._mdate}:{self._inode} {self._file}'
        return self.format_message(message)

    def get_message(self, event_mode=None, event_type=None):
        if event_mode is not None:
            self.event_mode = event_mode
        else:
            self.event_mode = choice(["real-time", "whodata", "scheduled"])

        if event_type is not None:
            self.event_type = event_type
        else:
            self.event_type = choice(["added", "modified", "deleted"])

        return self.generate_message()


class Sender:
    """This class sends events to the manager through a socket.

    Attributes:
        manager_address (str): IP of the manager.
        manager_port (str, optional): port used by remoted in the manager.
        protocol (str, optional): protocol used by remoted. tcp or udp.
        socket (socket): sock_stream used to connect with remoted.

    Examples:
        To create a Sender, you need to create an agent first, and then, create the sender. Finally, to send messages
        you will need to use both agent and sender to create an injector.
        >>> import wazuh_testing.tools.agent_simulator as ag
        >>> manager_address = "172.17.0.2"
        >>> agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0")
        >>> sender = ag.Sender(manager_address, protocol="tcp")
    """
    def __init__(self, manager_address, manager_port="1514", protocol="tcp"):
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.protocol = protocol
        if self.protocol == "tcp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.manager_address, int(self.manager_port)))
        if self.protocol == "udp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_event(self, event):
        if self.protocol == "tcp":
            length = pack('<I', len(event))
            self.socket.send(length + event)
        if self.protocol == "udp":
            self.socket.sendto(event, (self.manager_address,
                                       int(self.manager_port)))


class Injector:
    """This class simulates a daemon used to send and receive messages with the manager.

    Each `Agent` needs an injector and a sender to be able to communicate with the manager. This class will create
    a thread using `InjectorThread` which will behave similarly to an UNIX daemon. The `InjectorThread` will
    send and receive the messages using the `Sender`

    Attributes:
        sender (Sender): sender used to connect to the sockets and send messages.
        agent (agent): agent owner of the injector and the sender.
        thread_number (int): total number of threads created. This may change depending on the modules used in the
                             agent.
        threads (list): list containing all the threads created.

    Examples:
        To create an Injector, you need to create an agent, a sender and then, create the injector using both of them.
        >>> import wazuh_testing.tools.agent_simulator as ag
        >>> manager_address = "172.17.0.2"
        >>> agent = ag.Agent(manager_address, "aes", os="debian8", version="4.2.0")
        >>> sender = ag.Sender(manager_address, protocol="tcp")
        >>> injector = ag.Injector(sender, agent)
        >>> injector.run()
    """

    def __init__(self, sender, agent):
        self.sender = sender
        self.agent = agent
        self.thread_number = 0
        self.threads = []
        for module, config in self.agent.modules.items():
            if config["status"] == "enabled":
                self.threads.append(
                    InjectorThread(self.thread_number, f"Thread-{self.agent.id}{module}", self.sender,
                                   self.agent, module))
                self.thread_number += 1

    def run(self):
        """Start the daemon to send and receive messages for all the threads."""
        for thread in range(self.thread_number):
            self.threads[thread].setDaemon(True)
            self.threads[thread].start()

    def stop_receive(self):
        """Stop the daemon for all the threads."""
        for thread in range(self.thread_number):
            self.threads[thread].stop_rec()
        sleep(2)
        self.sender.socket.close()


class InjectorThread(threading.Thread):
    """This class creates a thread who will create and send the events to the manager for each module.

    Attributes:
        thread_id (int): ID of the thread.
        name (str): name of the thread. It is composed as Thread-{agent.id}{module}.
        sender (Sender): sender used to connect to the sockets and send messages.
        agent (Agent): agent owner of the injector and the sender.
        module (str): module used to send events (fim, syscollector, etc).
        stop_thread (int): 0 if the thread is running, 1 if it is stopped.
    """
    def __init__(self, thread_id, name, sender, agent, module):
        super(InjectorThread, self).__init__()
        self.thread_id = thread_id
        self.name = name
        self.sender = sender
        self.agent = agent
        self.totalMessages = 0
        self.module = module
        self.stop_thread = 0

    def keep_alive(self):
        """Send a keep alive message from the agent to the manager."""
        sleep(10)
        logging.debug("Startup - {}({})".format(self.agent.name, self.agent.id))
        self.sender.send_event(self.agent.startup_msg)
        self.sender.send_event(self.agent.keep_alive_msg)
        start_time = time()
        while self.stop_thread == 0:
            # Send agent keep alive
            logging.debug(f"KeepAlive - {self.agent.name}({self.agent.id})")
            self.sender.send_event(self.agent.keep_alive_msg)
            sleep(self.agent.modules["keepalive"]["frequency"] -
                  ((time() - start_time) %
                   self.agent.modules["keepalive"]["frequency"]))

    def fim(self):
        """Send a File Integrity Monitoring message from the agent to the manager."""
        """Send a File Integrity Monitoring message from the agent to the manager."""
        sleep(10)
        start_time = time()
        # Loop events
        while self.stop_thread == 0:
            event = self.agent.create_event(self.agent.fim.get_message())
            self.sender.send_event(event)
            self.totalMessages += 1
            if self.totalMessages % self.agent.modules["fim"]["eps"] == 0:
                sleep(1.0 - ((time() - start_time) % 1.0))

    def fim_integrity(self):
        """Send an integrity FIM message from the agent to the manager"""
        sleep(10)
        start_time = time()
        # Loop events
        while self.stop_thread == 0:
            event = self.agent.create_event(self.agent.fim_integrity.get_message())
            self.sender.send_event(event)
            self.totalMessages += 1
            if self.totalMessages % self.agent.modules["fim_integrity"]["eps"] == 0:
                sleep(1.0 - ((time() - start_time) % 1.0))

    def inventory(self):
        """Send an inventory message of syscollector from the agent to the manager."""
        sleep(10)
        start_time = time()
        while self.stop_thread == 0:
            # Send agent inventory scan
            logging.debug(f"Scan started - {self.agent.name}({self.agent.id}) - "
                  f"syscollector({self.agent.inventory.inventory_path})")
            scan_id = int(time())  # Random start scan ID
            for item in self.agent.inventory.inventory:
                event = self.agent.create_event(item.replace("<scan_id>", str(scan_id)))
                self.sender.send_event(event)
                self.totalMessages += 1
                if self.totalMessages % self.agent.modules["syscollector"]["eps"] == 0:
                    self.totalMessages = 0
                    sleep(1.0 - ((time() - start_time) % 1.0))
            logging.debug("Scan ended - {self.agent.name}({self.agent.id}) - "
                  f"syscollector({self.agent.inventory.inventory_path})")
            sleep(self.agent.modules["syscollector"]["frequency"] - ((time() - start_time)
                                                                     % self.agent.modules["syscollector"]["frequency"]))

    def rootcheck(self):
        """Send a rootcheck message from the agent to the manager."""
        sleep(10)
        start_time = time()
        while self.stop_thread == 0:
            # Send agent rootcheck scan
            logging.debug(f"Scan started - {self.agent.name}({self.agent.id}) "
                  f"- rootcheck({self.agent.rootcheck.rootcheck_path})")
            for item in self.agent.rootcheck.rootcheck:
                self.sender.send_event(self.agent.create_event(item))
                self.totalMessages += 1
                if self.totalMessages % self.agent.modules["rootcheck"]["eps"] == 0:
                    self.totalMessages = 0
                    sleep(1.0 - ((time() - start_time) % 1.0))
            logging.debug(f"Scan ended - {self.agent.name}({self.agent.id}) - rootcheck({self.agent.rootcheck.rootcheck_path})")
            sleep(self.agent.modules["rootcheck"]["frequency"] - ((time() - start_time)
                                                                  % self.agent.modules["rootcheck"]["frequency"]))

    def run(self):
        """Start the thread that will send messages to the manager."""
        # message = "1:/var/log/syslog:Jan 29 10:03:41 master sshd[19635]:
        #   pam_unix(sshd:session): session opened for user vagrant by (uid=0)
        #   uid: 0"
        logging.debug(f"Starting - {self.agent.name}({self.agent.id})({self.agent.os}) - {self.module}")
        if self.module == "keepalive":
            self.keep_alive()
        elif self.module == "fim":
            self.fim()
        elif self.module == "syscollector":
            self.inventory()
        elif self.module == "rootcheck":
            self.rootcheck()
        elif self.module == "fim_integrity":
            self.fim_integrity()
        elif self.module == "receive_messages":
            self.agent.receive_message(self.sender)
        else:
            logging.debug("Module unknown: {}".format(self.module))
            pass

    def stop_rec(self):
        """Stop the thread to avoid sending any more messages."""
        if self.module == "receive_messages":
            self.agent.stop_receiver()
        else:
            self.stop_thread = 1


def create_agents(agents_number, manager_address, cypher, fim_eps=None, authd_password=None, agents_os=None,
                  agents_version=None):
    """Create a list of generic agents

    This will create a list with `agents_number` amount of agents. All of them will be registered in the same manager.

    Args:
        agents_number (int): total number of agents.
        manager_address (str): IP address of the manager.
        cypher (str): cypher used for the communications. It may be aes or blowfish.
        fim_eps (int, optional): total number of EPS produced by FIM.
        authd_password (str, optional): password to enroll an agent.
        agents_os (list, optional): list containing different operative systems for the agents.
        agents_version (list, optional): list containing different version of the agent.

    Returns:
        list: list of the new virtual agents.
    """
    global agent_count
    # Read client.keys and create virtual agents
    agents = []
    for agent in range(agents_number):
        agent_os = agents_os[agent] if agents_os is not None else None
        agent_version = agents_version[agent] if agents_version is not None else None

        agents.append(Agent(manager_address, cypher, fim_eps=fim_eps, authd_password=authd_password,
                            os=agent_os, version=agent_version))

        agent_count = agent_count + 1

    return agents
