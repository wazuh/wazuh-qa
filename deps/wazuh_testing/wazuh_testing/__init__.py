# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import sys
import os
import yaml
import platform
from collections import defaultdict


if sys.platform == 'win32':
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'ossec.log')
    SYSCOLLECTOR_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'syscollector', 'db', 'local.db')
else:
    if sys.platform == 'darwin':
        WAZUH_PATH = os.path.join("/", "Library", "Ossec")
    else:
        WAZUH_PATH = os.path.join("/var", "ossec")
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    SYSCOLLECTOR_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'syscollector', 'db', 'local.db')


WAZUH_CONF_PATH = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
WAZUH_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc' if platform.system() == 'Linux' else '', 'client.keys')
DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
QUEUE_SOCKETS_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets')
WAZUH_DB_SOCKET_PATH = os.path.join(QUEUE_DB_PATH, 'wdb')
CVE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'vulnerabilities', 'cve.db')
ALERTS_JSON_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.json')
ARCHIVES_LOG_PATH = os.path.join(WAZUH_PATH, 'logs', 'archives', 'archives.log')
ARCHIVES_JSON_PATH = os.path.join(WAZUH_PATH, 'logs', 'archives', 'archives.json')
CPE_HELPER_PATH = os.path.join(WAZUH_PATH, 'queue', 'vulnerabilities', 'dictionaries', 'cpe_helper.json')
WAZUH_API_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'api.yaml')
WAZUH_SECURITY_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'security', 'security.yaml')
API_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.log')
API_JSON_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.json')
API_LOG_FOLDER = os.path.join(WAZUH_PATH, 'logs', 'api')
WAZUH_TESTING_PATH = os.path.dirname(os.path.abspath(__file__))

# Daemons
LOGCOLLECTOR_DAEMON = 'wazuh-logcollector'
AGENTLESS_DAEMON = 'wazuh-agentlessd'
CSYSLOG_DAEMON = 'wazuh-csyslogd'
REMOTE_DAEMON = 'wazuh-remoted'
ANALYSISD_DAEMON = 'wazuh-analysisd'
API_DAEMON = 'wazuh-apid'
MAIL_DAEMON = 'wazuh-maild'
SYSCHECK_DAEMON = 'wazuh-syscheckd'
EXEC_DAEMON = 'wazuh-execd'
MODULES_DAEMON = 'wazuh-modulesd'
CLUSTER_DAEMON = 'wazuh-clusterd'
INTEGRATOR_DAEMON = 'wazuh-integratord'
MONITOR_DAEMON = 'wazuh-monitord'
DB_DAEMON = 'wazuh-db'
AGENT_DAEMON = 'wazuh-agentd'

API_DAEMONS_REQUIREMENTS = [API_DAEMON, DB_DAEMON, EXEC_DAEMON, ANALYSISD_DAEMON, REMOTE_DAEMON, MODULES_DAEMON]

# Paths
SYSLOG_SIMULATOR = os.path.join(WAZUH_TESTING_PATH, 'scripts', 'syslog_simulator.py')
ANALYSISD_STATE = os.path.join(WAZUH_PATH, 'var', 'run', 'wazuh-analysisd.state')

# Timeouts
T_2 = 2
T_5 = 5
T_10 = 10
T_20 = 20
T_30 = 30
T_60 = 60


# Protocols
UDP = 'UDP'
TCP = 'TCP'
TCP_UDP = 'TCP,UDP'


def is_udp(protocol):
    return protocol.upper() == UDP


def is_tcp(protocol):
    return protocol.upper() == TCP


def is_tcp_udp(protocol):
    _protocol = protocol.replace(' ', '').upper().split(',')
    _protocol.sort()
    return ','.join(_protocol) == TCP_UDP


class Parameters:
    """Class to allocate all global parameters for testing"""

    def __init__(self):
        timeouts = defaultdict(lambda: 10)
        timeouts['linux'] = 5
        timeouts['darwin'] = 5
        self._default_timeout = timeouts[sys.platform]
        self._fim_database_memory = False
        self._gcp_project_id = None
        self._gcp_subscription_name = None
        self._gcp_credentials_file = None
        self._gcp_topic_name = None
        self._gcp_configuration_file = None
        self._gcp_credentials = None
        self._fim_mode = []

    @property
    def default_timeout(self):
        """Getter method for the default timeout property

        Returns:
            int: representing the default timeout in seconds
        """
        return self._default_timeout

    @default_timeout.setter
    def default_timeout(self, value):
        """Setter method for the default timeout property

        Args:
            value (int): New value for the default timeout. Must be in seconds.
        """
        self._default_timeout = value

    @property
    def fim_database_memory(self):
        """Getter method for the `fim_database_memory` property

        Returns:
            bool: representing if `fim_database_memory` is activated
        """
        return self._fim_database_memory

    @fim_database_memory.setter
    def fim_database_memory(self, value):
        """Setter method for the `fim_database_memory` property

        Args:
            value (bool): New value for the `fim_database_memory`.
        """
        self._fim_database_memory = value

    @property
    def current_configuration(self):
        """Getter method for the current configuration property

        Returns:
            dict: A dictionary containing the current configuration.
        """
        return self._current_configuration

    @current_configuration.setter
    def current_configuration(self, value):
        """Setter method for the current configuration property

        Args:
            value (dict): New value for the current configuration.
        """
        self._current_configuration = value

    @property
    def gcp_project_id(self):
        """Getter method for the `gcp_project_id` property

        Returns:
            str: Google Cloud project id `gcp_project_id`.
        """
        return self._gcp_project_id

    @gcp_project_id.setter
    def gcp_project_id(self, value):
        """Setter method for the `gcp_project_id` property

        Args:
            value (string): New value for the `gcp_project_id`.
        """
        self._gcp_project_id = value

    @property
    def gcp_subscription_name(self):
        """Getter method for the `gcp_subscription_name` property

        Returns:
           str: Google Cloud subscription name `gcp_subscription_name`.
        """
        return self._gcp_subscription_name

    @gcp_subscription_name.setter
    def gcp_subscription_name(self, value):
        """Setter method for the `gcp_subscription_name` property

        Args:
            value (string): New value for the `gcp_subscription_name`.
        """
        self._gcp_subscription_name = value

    @property
    def gcp_credentials_file(self):
        """Getter method for the `gcp_credentials_file` property

        Returns:
            str: path of `gcp_credentials_file`.
        """
        return self._gcp_credentials_file

    @gcp_credentials_file.setter
    def gcp_credentials_file(self, value):
        """Setter method for the `gcp_credentials_file` property

        Args:
            value (string): New value for the `gcp_credentials_file`.
        """
        self._gcp_credentials_file = value

    @property
    def gcp_topic_name(self):
        """Getter method for the `gcp_topic_name` property

        Returns:
            str: Google Cloud topic name `gcp_topic_name`.
        """
        return self._gcp_topic_name

    @gcp_topic_name.setter
    def gcp_topic_name(self, value):
        """Setter method for the `gcp_topic_name` property

        Args:
            value (string): New value for the `gcp_topic_name`.
        """
        self._gcp_topic_name = value

    @property
    def gcp_credentials(self):
        """Getter method for the `gcp_credentials` property

        Returns:
            str: Google Cloud topic name `gcp_credentials`.
        """
        return self._gcp_credentials

    @gcp_credentials.setter
    def gcp_credentials(self, value):
        """Setter method for the `gcp_credentials` property

        Args:
            value (string): New value for the `gcp_credentials`.
        """
        self._gcp_credentials = value

    @property
    def gcp_configuration_file(self):
        """Getter method for the `gcp_configuration_file` property

        Returns:
            str: Google Cloud topic name `gcp_configuration_file`.
        """
        return self._gcp_configuration_file

    @gcp_configuration_file.setter
    def gcp_configuration_file(self, value):
        """Setter method for the `gcp_configuration_file` property

        Args:
            value (string): New value for the `gcp_configuration_file`.
        """
        if not os.path.exists(value):
            return

        # Overwrite global parameters with the configuration file
        with open(value) as stream:
            gcp_conf = yaml.safe_load(stream)

        if 'project_id' in gcp_conf:
            self.gcp_project_id = gcp_conf['project_id']
        if 'subscription' in gcp_conf:
            self.gcp_subscription_name = gcp_conf['subscription']
        if 'topic' in gcp_conf:
            self.gcp_topic_name = gcp_conf['topic']
        if 'credential_path' in gcp_conf:
            self.gcp_credentials_file = gcp_conf['credential_path']
        if 'credentials' in gcp_conf:
            self.gcp_credentials = gcp_conf['credentials']

        self._gcp_configuration_file = value

    @property
    def fim_mode(self):
        """Getter method for the `fim_mode` property

        Returns:
            list: FIM modes that will be used.
        """
        return self._fim_mode

    @fim_mode.setter
    def fim_mode(self, value):
        """Setter method for the `fim_mode` property

        Args:
            value (list): New value for the `fim_mode`.
        """
        self._fim_mode = value


global_parameters = Parameters()
logger = logging.getLogger('wazuh_testing')
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)
