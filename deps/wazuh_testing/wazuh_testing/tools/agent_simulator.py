#!/usr/bin/python
# Wazuh agents load simulator
# Copyright (C) 2015-2021, Wazuh Inc.
# January 28, 2020.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Python 3.7 or superior
# Dependencies
# pip3 install pycryptodome

import hashlib
import json
import os
import socket
import ssl
import threading
import zlib
from random import randint, sample, choice
from stat import S_IFLNK, S_IFREG, S_IRWXU, S_IRWXG, S_IRWXO
from string import ascii_letters, digits
from struct import pack
from time import mktime, localtime, sleep, time

from wazuh_testing.tools.remoted_sim import Cipher

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                          'data')

os_list = ["debian7", "debian8", "debian9", "debian10", "ubuntu12.04",
           "ubuntu14.04", "ubuntu16.04", "ubuntu18.04", "mojave"]
agent_count = 1


class Agent:
    def __init__(self, manager_address, cypher="aes", os=None,
                 inventory_sample=None, rootcheck_sample=None,
                 id=None, name=None, key=None, version="v3.12.0",
                 fim_eps=None, fim_integrity_eps=None,
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

    # Set up agent: Keep alive, encryption key and start up msg.
    def setup(self):
        self.set_os()
        if self.id is None and self.name is None and self.key is None:
            self.set_name()
            self.register()
        self.create_encryption_key()
        self.createKeepAlive()
        self.createHCStartup()
        self.initializeModules()

    # Pick random OS
    def set_os(self):
        if self.os is None:
            self.os = os_list[agent_count % len(os_list) - 1]

    # Set variables related to wpk simulated responses
    def set_wpk_variables(self, sha=None, upgrade_exec_result=None,
                          upgrade_notification=False, upgrade_script_result=0,
                          stage_disconnect=None):
        self.sha_key = sha
        self.upgrade_exec_result = upgrade_exec_result
        self.send_upgrade_notification = upgrade_notification
        self.upgrade_script_result = upgrade_script_result
        self.stage_disconnect = stage_disconnect

    # Set agent name
    def set_name(self):
        random_string = ''.join(sample('0123456789abcdef' * 2, 8))
        if self.inventory_sample is None:
            self.name = "{}-{}-{}".format(agent_count, random_string, self.os)
        else:
            inventory_string = self.inventory_sample.replace(".", "")
            self.name = "{}-{}-{}-{}".format(agent_count,
                                             random_string, self.os,
                                             inventory_string)

    # Request agent key
    def register(self):
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
        print("Registration - {}({})".format(self.name, self.id))

    # Add the Wazuh custom padding to each event sent
    @staticmethod
    def wazuh_padding(compressed_event):
        padding = 8
        extra = len(compressed_event) % padding
        if extra > 0:
            padded_event = (b'!' * (padding - extra)) + compressed_event
        else:
            padded_event = (b'!' * padding) + compressed_event
        return padded_event

    # Generate encryption key (using agent metadata and key)
    def create_encryption_key(self):
        id = self.id.encode()
        name = self.name.encode()
        key = self.key.encode()
        sum1 = (hashlib.md5((hashlib.md5(name).hexdigest().encode()
                             + hashlib.md5(id).hexdigest().encode())).hexdigest().encode())
        sum1 = sum1[:15]
        sum2 = hashlib.md5(key).hexdigest().encode()
        key = sum2 + sum1
        self.encryption_key = key

    # Compose event from raw message
    @staticmethod
    def compose_event(message):
        message = message.encode()
        random_number = b'55555'
        global_counter = b'1234567891'
        split = b':'
        local_counter = b'5555'
        msg = random_number + global_counter + split + local_counter \
              + split + message
        msg_md5 = hashlib.md5(msg).hexdigest()
        event = msg_md5.encode() + msg
        return event

    # Encrypt event AES or Blowfish
    def encrypt(self, padded_event):
        encrypted_event = None
        if self.cypher == "aes":
            encrypted_event = Cipher(padded_event,
                                     self.encryption_key).encrypt_aes()
        if self.cypher == "blowfish":
            encrypted_event = Cipher(padded_event,
                                     self.encryption_key).encrypt_blowfish()
        return encrypted_event

    # Add event headers for AES or Blowfish Cyphers
    def headers(self, agentid, encrypted_event):
        headers_event = None
        if self.cypher == "aes":
            header = "!{0}!#AES:".format(agentid).encode()
        if self.cypher == "blowfish":
            header = "!{0}!:".format(agentid).encode()
        headers_event = header + encrypted_event
        return headers_event

    def createEvent(self, message):
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

    def receiveMessage(self, sender):
        while self.stop_receive == 0:
            buffer_array = None
            if sender.protocol == 'tcp':
                rcv = sender.socket.recv(4)
                if len(rcv) == 4:
                    data_len = ((rcv[3] & 0xFF) << 24) | \
                               ((rcv[2] & 0xFF) << 16) | \
                               ((rcv[1] & 0xFF) << 8) | \
                               (rcv[0] & 0xFF)

                    buffer_array = sender.socket.recv(data_len)

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
                msg_removeheader = bytes(buffer_array[5:])
                msg_decrypted = Cipher(msg_removeheader, self.encryption_key) \
                    .decrypt_aes()
            else:
                msg_removeheader = bytes(buffer_array[1:])
                msg_decrypted = Cipher(msg_removeheader, self.encryption_key) \
                    .decrypt_blowfish()

            padding = 0
            while (msg_decrypted):
                if msg_decrypted[padding] == 33:
                    padding += 1
                else:
                    break
            msg_removepadding = msg_decrypted[padding:]
            msg_decompress = zlib.decompress(msg_removepadding)
            msg_decoded = msg_decompress.decode('ISO-8859-1')
            self.processMessage(sender, msg_decoded)

    def stop_receiver(self):
        self.stop_receive = 1

    def processMessage(self, sender, message):
        msg_decoded_list = message.split(' ')
        if 'com' in msg_decoded_list or 'upgrade' in msg_decoded_list:
            self.processCommand(sender, msg_decoded_list)

    def processCommand(self, sender, message_list):
        command = None
        if 'com' in message_list:
            com_index = message_list.index('com')
            command = message_list[com_index + 1]
        else:
            com_index = message_list.index('upgrade')
            json_command = json.loads(message_list[com_index + 1])
            command = json_command['command']
        if command in ['lock_restart', 'open', 'write', 'close',
                       'clear_upgrade_result']:
            if command == 'lock_restart' and \
                    self.stage_disconnect == 'lock_restart':
                self.stop_receive = 1
            elif command == 'open' and self.stage_disconnect == 'open':
                self.stop_receive = 1
            elif command == 'write' and self.stage_disconnect == 'write':
                self.stop_receive = 1
            elif command == 'close' and self.stage_disconnect == 'close':
                self.stop_receive = 1
            elif command == 'clear_upgrade_result' and \
                    self.stage_disconnect == 'clear_upgrade_result':
                self.stop_receive = 1
            else:
                if self.short_version < "4.1" or command == 'lock_restart':
                    sender.sendEvent(self.createEvent(f'#!-req {message_list[1]} ok '))
                else:
                    sender.sendEvent(self.createEvent(f'#!-req {message_list[1]} '
                                                      f'{{"error":0, "message":"ok", "data":[]}} '))
        elif command == 'sha1':
            # !-req num ok {sha}
            if self.sha_key:
                if command == 'sha1' and self.stage_disconnect == 'sha1':
                    self.stop_receive = 1
                else:
                    if self.short_version < "4.1":
                        sender.sendEvent(self.createEvent(f'#!-req {message_list[1]} '
                                                          f'ok {self.sha_key}'))
                    else:
                        sender.sendEvent(self.createEvent(f'#!-req {message_list[1]} {{"error":0, '
                                                          f'"message":"{self.sha_key}", "data":[]}}'))
            else:
                raise ValueError(f'WPK SHA key should be configured in agent')
        elif command == 'upgrade':
            if self.upgrade_exec_result:
                if command == 'upgrade' and self.stage_disconnect == 'upgrade':
                    self.stop_receive = 1
                else:
                    if self.short_version < "4.1":
                        sender.sendEvent(self.createEvent(
                            f'#!-req {message_list[1]} ok '
                            f'{self.upgrade_exec_result}'))
                    else:
                        sender.sendEvent(self.createEvent(f'#!-req {message_list[1]} {{"error":0, '
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
                        sender.sendEvent(self.createEvent("u:upgrade_module:"
                                                          + json.dumps(
                            upgrade_update_status_message)))
            else:
                raise ValueError(f'Execution result should be configured \
                                 in agent')
        else:
            raise ValueError(f'Unrecongnized command {command}')

    def createHCStartup(self):
        msg = "#!-agent startup "
        self.startup_msg = self.createEvent(msg)

    def createKeepAlive(self):
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
        self.keep_alive_msg = self.createEvent(msg)

    def initializeModules(self):
        if self.modules["syscollector"]["status"] == "enabled":
            self.inventory = Inventory(self.os, self.inventory_sample)
        if self.modules["rootcheck"]["status"] == "enabled":
            self.rootcheck = Rootcheck(self.rootcheck_sample)
        if self.modules["fim"]["status"] == "enabled":
            self.fim = GeneratorFIM(self.id, self.name, self.short_version)
        if self.modules["fim_integrity"]["status"] == "enabled":
            self.fim_integrity = GeneratorIntegrityFIM(self.id, self.name,
                                                       self.short_version)


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
            inventory_files = os.listdir("inventory/{}".format(self.os))
            self.inventory_path = "inventory/{}/{}" \
                .format(self.os, choice(inventory_files))
        else:
            self.inventory_path = "inventory/{}/{}" \
                .format(self.os, self.inventory_sample)
        with open(self.inventory_path) as fp:
            line = fp.readline()
            while line:
                if not line.startswith("#"):
                    msg = "{0}:{1}:{2}".format(self.SYSCOLLECTOR_MQ,
                                               self.SYSCOLLECTOR,
                                               line.strip("\n"))
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
                    msg = "{0}:{1}:{2}".format(self.ROOTCHECK_MQ,
                                               self.ROOTCHECK,
                                               line.strip("\n"))
                    self.rootcheck.append(msg)
                line = fp.readline()


class GeneratorIntegrityFIM:
    def __init__(self, agent_id, agent_name, agent_version):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.INTEGRITY_MQ = "5"
        self.event_type = None
        self.fim_generator = GeneratorFIM(self.agent_id, self.agent_name,
                                          self.agent_version)

    def formatMessage(self, message):
        return '{0}:[{1}] ({2}) any->syscheck:{3}'.format(self.INTEGRITY_MQ,
                                                          self.agent_id,
                                                          self.agent_name,
                                                          message)

    def generateMessage(self):
        data = None
        if self.event_type == "integrity_check_global" or \
                self.event_type == "integrity_check_left" or \
                self.event_type == "integrity_check_right":
            id = int(time())
            data = {"id": id,
                    "begin": self.fim_generator.randfile(),
                    "end": self.fim_generator.randfile(),
                    "checksum": self.fim_generator.randsha1()}

        if self.event_type == "integrity_clear":
            id = int(time())
            data = {"id": id}

        if self.event_type == "state":
            timestamp = int(time())
            self.fim_generator.generateAttributes()
            attributes = self.fim_generator.getAttributes()
            data = {"path": self.fim_generator._file,
                    "timestamp": timestamp,
                    "attributes": attributes}

        message = json.dumps({"component": "syscheck",
                              "type": self.event_type,
                              "data": data})
        return self.formatMessage(message)

    def getMessage(self, event_type=None):
        if event_type is not None:
            self.event_type = event_type
        else:
            self.event_type = choice(["integrity_check_global",
                                      "integrity_check_left",
                                      "integrity_check_right",
                                      "integrity_clear",
                                      "state"])
            # self.event_type = choice(["state"])

        return self.generateMessage()


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

    def randfile(self):
        self._file = self.FILE_ROOT + ''.join(sample(ascii_letters + digits,
                                                     self.DEFAULT_FILE_LENGTH))
        return self._file

    def randsize(self):
        self._size = randint(-1, self.MAX_SIZE)
        return self._size

    def randmode(self):
        self._mode = choice((S_IFREG, S_IFLNK))

        if self._mode == S_IFLNK:
            self._mode |= S_IRWXU | S_IRWXG | S_IRWXO
            self._md5 = 'xxx'
            self._sha1 = 'xxx'
        else:
            s = sample((S_IRWXU, S_IRWXG, S_IRWXO), 2)
            self._mode |= s[0] | s[1]

        return self._mode

    def randuid(self):
        self._uid = choice(list(self.USERS.keys()))
        self._uname = self.USERS[self._uid]
        return self._uid, self._uname

    def randgid(self):
        self._gid = choice(list(self.USERS.keys()))
        self._gname = self.USERS[self._gid]
        return self._gid, self._gname

    def randmd5(self):
        if self._mode & S_IFREG == S_IFREG:
            self._md5 = ''.join(sample('0123456789abcdef' * 2, 32))

        return self._md5

    def randsha1(self):
        if self._mode & S_IFREG == S_IFREG:
            self._sha1 = ''.join(sample('0123456789abcdef' * 3, 40))

        return self._sha1

    def randsha256(self):
        if self._mode & S_IFREG == S_IFREG:
            self._sha256 = ''.join(sample('0123456789abcdef' * 4, 64))

        return self._sha256

    def randtime(self):
        self._mdate += randint(1, self.MAX_TIMEDIFF)
        return self._mdate

    def randinode(self):
        self._inode = randint(1, self.MAX_INODE)
        return self._inode

    def generateAttributes(self):
        self.randfile()
        self.randsize()
        self.randmode()
        self.randuid()
        self.randgid()
        self.randmd5()
        self.randsha1()
        self.randsha256()
        self.randtime()
        self.randinode()

    def checkChangedAttributes(self, attributes, old_attributes):
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

    def getAttributes(self):
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

    def formatMessage(self, message):
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

    def generateMessage(self):
        if self.agent_version >= "3.12":
            if self.event_type == "added":
                timestamp = int(time())
                self.generateAttributes()
                attributes = self.getAttributes()
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes}
            elif self.event_type == "modified":
                timestamp = int(time())
                self.generateAttributes()
                attributes = self.getAttributes()
                self.generateAttributes()
                old_attributes = self.getAttributes()
                changed_attributes = \
                    self.checkChangedAttributes(attributes, old_attributes)
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes,
                        "old_attributes": old_attributes,
                        "changed_attributes": changed_attributes}
            else:
                timestamp = int(time())
                self.generateAttributes()
                attributes = self.getAttributes()
                data = {"path": self._file, "mode": self.event_mode,
                        "type": self.event_type, "timestamp": timestamp,
                        "attributes": attributes}

            message = json.dumps({"type": "event", "data": data})

        else:
            self.generateAttributes()
            message = '{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}:{8}:{9} {10}'.format(
                self._size, self._mode, self._uid, self._gid, self._md5,
                self._sha1, self._uname, self._gname, self._mdate,
                self._inode, self._file)

        return self.formatMessage(message)

    def getMessage(self, event_mode=None, event_type=None):
        if event_mode is not None:
            self.event_mode = event_mode
        else:
            self.event_mode = choice(["real-time", "whodata", "scheduled"])

        if event_type is not None:
            self.event_type = event_type
        else:
            self.event_type = choice(["added", "modified", "deleted"])

        return self.generateMessage()


class Sender:
    def __init__(self, manager_address, manager_port="1514", protocol="tcp"):
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.protocol = protocol
        if self.protocol == "tcp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.manager_address, int(self.manager_port)))
        if self.protocol == "udp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def sendEvent(self, event):
        if self.protocol == "tcp":
            length = pack('<I', len(event))
            self.socket.send(length + event)
            # return(self.socket.recv(2048))
            # self.socket.close() # Not closing.
            # It will close the socket on Ctrl+C.
        if self.protocol == "udp":
            self.socket.sendto(event, (self.manager_address,
                                       int(self.manager_port)))


class Injector:
    def __init__(self, sender, agent):
        self.sender = sender
        self.agent = agent
        self.thread_number = 0
        self.threads = []
        for module, config in self.agent.modules.items():
            if config["status"] == "enabled":
                self.threads.append(InjectorThread(self.thread_number,
                                                   "Thread-"
                                                   + str(self.agent.id)
                                                   + str(module),
                                                   self.sender,
                                                   self.agent, module))
                self.thread_number += 1

    def run(self):
        for thread in range(self.thread_number):
            self.threads[thread].setDaemon(True)
            self.threads[thread].start()

    def stop_receive(self):
        for thread in range(self.thread_number):
            self.threads[thread].stop_rec()
        sleep(2)
        self.sender.socket.close()


class InjectorThread(threading.Thread):
    def __init__(self, threadID, name, sender, agent, module):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.sender = sender
        self.agent = agent
        self.totalMessages = 0
        self.module = module
        self.stop_thread = 0

    def keepalive(self):
        sleep(10)
        print("Startup - {}({})".format(self.agent.name, self.agent.id))
        self.sender.sendEvent(self.agent.startup_msg)
        self.sender.sendEvent(self.agent.keep_alive_msg)
        starttime = time()
        while self.stop_thread == 0:
            # Send agent keep alive
            print("KeepAlive - {}({})".format(self.agent.name, self.agent.id))
            self.sender.sendEvent(self.agent.keep_alive_msg)
            sleep(self.agent.modules["keepalive"]["frequency"] -
                  ((time() - starttime) %
                   self.agent.modules["keepalive"]["frequency"]))

    def fim(self):
        sleep(10)
        starttime = time()
        # Loop events
        while self.stop_thread == 0:
            # event = self.agent.createEvent(
            #  self.agent.fim.getMessage(event_type="added"))
            event = self.agent.createEvent(self.agent.fim.getMessage())
            self.sender.sendEvent(event)
            self.totalMessages += 1
            if self.totalMessages % self.agent.modules["fim"]["eps"] == 0:
                sleep(1.0 - ((time() - starttime) % 1.0))

    def fim_integrity(self):
        sleep(10)
        starttime = time()
        # Loop events
        while self.stop_thread == 0:
            event = \
                self.agent.createEvent(self.agent.fim_integrity.getMessage())
            self.sender.sendEvent(event)
            self.totalMessages += 1
            if self.totalMessages % \
                    self.agent.modules["fim_integrity"]["eps"] \
                    == 0:
                sleep(1.0 - ((time() - starttime) % 1.0))

    def inventory(self):
        sleep(10)
        starttime = time()
        while self.stop_thread == 0:
            # Send agent inventory scan
            print("Scan started - {}({}) - {}({})"
                  .format(self.agent.name,
                          self.agent.id,
                          "syscollector",
                          self.agent.inventory.inventory_path))
            scan_id = int(time())  # Random start scan ID
            for item in self.agent.inventory.inventory:
                event = self.agent.createEvent(item.replace("<scan_id>",
                                                            str(scan_id)))
                self.sender.sendEvent(event)
                self.totalMessages += 1
                if self.totalMessages % \
                        self.agent.modules["syscollector"]["eps"] == 0:
                    self.totalMessages = 0
                    sleep(1.0 - ((time() - starttime) % 1.0))
            print("Scan ended - {}({}) - {}({})"
                  .format(self.agent.name,
                          self.agent.id,
                          "syscollector",
                          self.agent.inventory.inventory_path))
            sleep(self.agent.modules["syscollector"]["frequency"]
                  - ((time() - starttime)
                     % self.agent.modules["syscollector"]["frequency"]))

    def rootcheck(self):
        sleep(10)
        starttime = time()
        while self.stop_thread == 0:
            # Send agent rootcheck scan
            print("Scan started - {}({}) - {}({})"
                  .format(self.agent.name,
                          self.agent.id,
                          "rootcheck",
                          self.agent.rootcheck.rootcheck_path))
            for item in self.agent.rootcheck.rootcheck:
                self.sender.sendEvent(self.agent.createEvent(item))
                self.totalMessages += 1
                if self.totalMessages % \
                        self.agent.modules["rootcheck"]["eps"] == 0:
                    self.totalMessages = 0
                    sleep(1.0 - ((time() - starttime) % 1.0))
            print("Scan ended - {}({}) - {}({})"
                  .format(self.agent.name,
                          self.agent.id,
                          "rootcheck",
                          self.agent.rootcheck.rootcheck_path))
            sleep(self.agent.modules["rootcheck"]["frequency"]
                  - ((time() - starttime)
                     % self.agent.modules["rootcheck"]["frequency"]))

    def run(self):
        # message = "1:/var/log/syslog:Jan 29 10:03:41 master sshd[19635]:
        #   pam_unix(sshd:session): session opened for user vagrant by (uid=0)
        #   uid: 0"
        print("Starting - {}({})({}) - {}"
              .format(self.agent.name, self.agent.id,
                      self.agent.os, self.module))
        if self.module == "keepalive":
            self.keepalive()
        elif self.module == "fim":
            self.fim()
        elif self.module == "syscollector":
            self.inventory()
        elif self.module == "rootcheck":
            self.rootcheck()
        elif self.module == "fim_integrity":
            self.fim_integrity()
        elif self.module == "receive_messages":
            self.agent.receiveMessage(self.sender)
        else:
            print("Module unknown: {}".format(self.module))
            pass

    def stop_rec(self):
        if self.module == "receive_messages":
            self.agent.stop_receiver()
        else:
            self.stop_thread = 1


def create_agents(agents_number, manager_address, cypher, fim_eps=None,
                  authd_password=None, os=None, version=None):
    global agent_count
    # Read client.keys and create virtual agents
    agents = []
    for agent in range(agents_number):
        if os is not None:
            agent_os = os[agent]
        else:
            agent_os = None

        agent_version = version[agent] if version is not None else None

        if authd_password is not None:
            agents.append(Agent(manager_address, cypher, fim_eps=fim_eps,
                                authd_password=authd_password, os=agent_os, version=agent_version))
        else:
            agents.append(Agent(manager_address, cypher, fim_eps=fim_eps,
                                os=agent_os, version=agent_version))
        agent_count = agent_count + 1
    return agents
