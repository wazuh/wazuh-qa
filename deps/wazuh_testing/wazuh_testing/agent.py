# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import platform
import re
import socket
import ssl
import json

from wazuh_testing.fim import change_internal_options
from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools import monitoring
from wazuh_testing import logger


DEFAULT_VALUES = {
    'enabled': 'yes',
    'manager_address': None,
    'port': 1515,
    'agent_name': socket.gethostname(),
    'groups': None,
    'agent_address': '127.0.0.1',
    'use_source_ip': 'no',
    'ssl_cipher': None,
    'server_ca_path': None,
    'agent_certificate_path': None,
    'agent_key_path': None,
    'authorization_pass_path': None
}

folder = 'etc' if platform.system() == 'Linux' else ''

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, folder, 'client.keys')  # for unix add 'etc'
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'manager.cert')
SERVER_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'manager.pem')
AGENT_KEY_PATH = os.path.join(WAZUH_PATH, folder, 'agent.key')
AGENT_CERT_PATH = os.path.join(WAZUH_PATH, folder, 'agent.cert')
AGENT_PEM_PATH = os.path.join(WAZUH_PATH, folder, 'agent.pem')
AUTHDPASS_PATH = os.path.join(WAZUH_PATH, folder, 'authd.pass')
AGENT_AUTH_BINARY_PATH = '/var/ossec/bin/agent-auth' if platform.system() == 'Linux' else \
    os.path.join(WAZUH_PATH, 'agent-auth.exe')

CONFIG_PATHS = {
    'SERVER_PEM_PATH': SERVER_PEM_PATH,
    'AGENT_CERT_PATH': AGENT_CERT_PATH,
    'AGENT_PEM_PATH': AGENT_PEM_PATH,
    'AGENT_KEY_PATH': AGENT_KEY_PATH,
    'PASSWORD_PATH': AUTHDPASS_PATH

}


class AgentAuthParser:
    """Creates the right invoke command to call agent-auth with all the different configurations"""
    def __init__(self, server_address=None, BINARY_PATH='/var/ossec/bin/agent-auth', sudo=False):
        self._command = []
        if sudo:
            self._command.append('sudo')
        self._command += [BINARY_PATH]
        if server_address:
            self._command += ['-m', server_address]

    def get_command(self):
        return self._command

    def add_agent_name(self, agent_name):
        self._command += ['-A', agent_name]

    def add_agent_adress(self, agent_adress):
        self._command += ['-I', agent_adress]

    def add_auto_negotiation(self):
        self._command += ['-a']

    def add_ciphers(self, ciphers):
        self._command += ['-c', ciphers]

    def add_agent_certificates(self, key, cert):
        self._command += ['-k', key, '-x', cert]

    def add_manager_ca(self, ca_cert):
        self._command += ['-v', ca_cert]

    def use_source_ip(self):
        self._command += ['-i']

    def add_password(self, password):
        self._command += ['-P', password]

    def add_groups(self, group_string):
        self._command += ['-G', group_string]


def clean_client_keys_file():
    try:
        client_file = open(CLIENT_KEYS_PATH, 'w')
        client_file.close()
    except IOError as exception:
        raise


def check_client_keys_file():
    """Wait until client key has been written"""

    def wait_key_changes(line):
        if 'Valid key received' in line:
            return line
        return None

    log_monitor = monitoring.FileMonitor(LOG_FILE_PATH)
    try:
        log_monitor.start(timeout=6, callback=wait_key_changes)
    except Exception:
        pass
    try:
        with open(CLIENT_KEYS_PATH) as client_file:
            client_line = client_file.readline()
            # check format key 4 items (id name ip key)
            if len(client_line.split(" ")) != 4:
                client_file.close()
                return False
            client_file.close()
            return f"OSSEC K:'{client_line[:-1]}'\n"
    except IOError:
        raise
    client_file.close()
    return False


def build_expected_request(configuration):
    expec_req = "OSSEC"
    if configuration.get('password'):
        expec_req = f"OSSEC PASS: {configuration['password']['value']} " + expec_req
    if configuration.get('agent_name'):
        expec_req += " A:'%s'" % configuration.get('agent_name')
    else:
        expec_req += " A:'%s'" % DEFAULT_VALUES["agent_name"]
    if configuration.get('groups'):
        expec_req += " G:'%s'" % configuration.get('groups')
    if configuration.get('agent_address'):
        expec_req += " IP:'%s'" % configuration.get('agent_address')
    elif configuration.get('use_source_ip') == 'yes':
        expec_req += " IP:'src'"
    elif DEFAULT_VALUES['use_source_ip'] == 'yes':
        expec_req += " IP:'src'"
    return expec_req + '\n'


def clean_password_file():
    try:
        client_file = open(AUTHDPASS_PATH, 'w')
        client_file.close()
    except IOError as exception:
        raise


def configure_enrollment(enrollment, enrollment_server, agent_name=socket.gethostname()):
    enrollment_server.clear()
    if enrollment:
        if enrollment.get('id'):
            enrollment_server.agent_id = enrollment.get('id')
        if enrollment.get('protocol') == 'TLSv1_1':
            enrollment_server\
                .mitm_enrollment.listener.set_ssl_configuration(
                    connection_protocol=ssl.PROTOCOL_TLS,
                    options=(ssl.OP_ALL |
                             ssl.OP_NO_TLSv1_2 | (ssl.OP_NO_TLSv1_3 if hasattr(ssl, 'OP_NO_TLSv1_3') else 0) |
                             ssl.OP_CIPHER_SERVER_PREFERENCE |
                             ssl.OP_NO_COMPRESSION),
                    cert_reqs=ssl.CERT_NONE)
        else:
            enrollment_server.mitm_enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2,
                                                                             options=None)
        if enrollment.get('check_certificate'):
            if enrollment['check_certificate']['valid'] == 'yes':
                # Store valid certificate
                enrollment_server.cert_controller.store_ca_certificate(
                    enrollment_server.cert_controller.get_root_ca_cert(),
                    SERVER_PEM_PATH)
            else:
                # Create another certificate
                enrollment_server.cert_controller.generate_agent_certificates(AGENT_KEY_PATH, SERVER_PEM_PATH,
                                                                              agent_name)
        if enrollment.get('agent_certificate'):
            enrollment_server.cert_controller.generate_agent_certificates(AGENT_KEY_PATH, AGENT_CERT_PATH, agent_name,
                                                                          signed=(enrollment['agent_certificate'][
                                                                                      'valid'] == 'yes')
                                                                          )
            enrollment_server.mitm_enrollment.listener.set_ssl_configuration(cert_reqs=ssl.CERT_REQUIRED,
                                                                             ca_cert=SERVER_PEM_PATH)
            enrollment_server.cert_controller.store_ca_certificate(enrollment_server.cert_controller.get_root_ca_cert(),
                                                                   SERVER_PEM_PATH)
        else:
            enrollment_server.mitm_enrollment.listener.set_ssl_configuration(cert_reqs=ssl.CERT_OPTIONAL)


def parse_configuration_string(configuration):
    for key, value in configuration.items():
        if isinstance(value, str):
            configuration[key] = value.format(**CONFIG_PATHS)


# Callbacks
def callback_state_interval_not_valid(line):
    match = re.match(r'.*Invalid definition for agent.state_interval:', line)
    return True if match is not None else None


def callback_state_interval_not_found(line):
    match = re.match(r".*Definition not found for: 'agent.state_interval'", line)
    return True if match is not None else None


def callback_state_file_not_enabled(line):
    match = re.match(r'.*State file is disabled', line)
    return True if match is not None else None


def callback_state_file_enabled(line):
    match = re.match(r'.*State file updating thread started', line)
    return True if match is not None else None


def callback_state_file_updated(line):
    match = re.match(r'.*Updating state file', line)
    return True if match is not None else None


def callback_ack(line):
    match = re.match(r".*Received message: '#!-agent ack ", line)
    return True if match is not None else None


def callback_keepalive(line):
    match = re.match(r'.*Sending keep alive', line)
    return True if match is not None else None


def callback_connected_to_server(line):
    match = re.match(r'.*Connected to the server', line)
    return True if match is not None else None


def set_state_interval(interval, internal_file_path):
    """Set agent.state_interval value on internal_options.conf
    Args:
        interval:
            - Different than `None`: set agent.state_interval
                                     value on internal_options.conf
            - `None`: agent.state_interval will be removed
                      from internal_options.conf
    """
    if interval is not None:
        change_internal_options('agent.state_interval', interval, internal_file_path, '.*')
    else:
        new_content = ''
        with open(internal_file_path) as opts:
            for line in opts:
                new_line = line if 'agent.state_interval' not in line else ''
                new_content += new_line

        with open(internal_file_path, 'w') as opts:
            opts.write(new_content)


def callback_detect_upgrade_ack_event(event_log):
    """Detect sending upgrade ACK event returning upgrade process result.

    Args:
        event_log (str): Event line logs.

    Returns:
        String: Upgrade result.
    """
    match = re.match(".*Sending upgrade ACK event: '(.*)'", event_log)
    if not match:
        return None
    else:
        try:
            json_event = json.loads(match.group(1))
            return json_event
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_upgrade_module_up():
    """Detect module agent upgrade started event.

    Args:
        event_log (str): Event line logs.

    Returns:
        callable: callback to detect this event.
    """
    return monitoring.make_callback(pattern='Module Agent Upgrade started', prefix=monitoring.MODULESD_DETECTOR_PREFIX)


def callback_exit_cleaning():
    """Detect exit cleaning message.

    Args:
        callable: callback to detect this event.

    Returns:
        callable: callback to detect this event.
    """
    return monitoring.make_callback(pattern='Exit Cleaning', prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_invalid_server_address(server_ip):
    msg = fr"ERROR: \(\d+\): Invalid server address found: '{server_ip}'"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_could_not_resolve_hostname(server_ip):
    msg = f"ERROR: Could not resolve hostname: {server_ip}"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_connected_to_manager_ip(server_ip, port='1515'):
    msg = f"Connected to enrollment service at '\[{server_ip}\]:{port}'"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.AGENT_DETECTOR_PREFIX)
