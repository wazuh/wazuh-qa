# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import platform
import subprocess

if sys.platform == 'win32':
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'ossec.log')
    PREFIX = os.path.join('c:', os.sep)
    GEN_OSSEC = None
    WAZUH_API_CONF = None
    WAZUH_SECURITY_CONF = None
    API_LOG_FILE_PATH = None

else:

    WAZUH_SOURCES = os.path.join('/', 'wazuh')

    if sys.platform == 'darwin':
        WAZUH_PATH = os.path.join("/", "Library", "Ossec")
        PREFIX = os.path.join('/', 'private', 'var', 'root')
        GEN_OSSEC = None
    else:
        WAZUH_PATH = os.path.join("/", "var", "ossec")
        GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')
        PREFIX = os.sep

    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_API_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'api.yaml')
    WAZUH_SECURITY_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'security', 'security.yaml')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    API_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.log')

    try:
        import grp
        import pwd

        OSSEC_UID = pwd.getpwnam("ossec").pw_uid
        OSSEC_GID = grp.getgrnam("ossec").gr_gid
    except (ImportError, KeyError, ModuleNotFoundError):
        pass


def get_version():

    if platform.system() in ['Windows', 'win32']:
        with open(os.path.join(WAZUH_PATH, 'VERSION'), 'r') as f:
            version = f.read()
            return version[:version.rfind('\n')]

    else:  # Linux, sunos5, darwin, aix...
        return subprocess.check_output([
          f"{WAZUH_PATH}/bin/wazuh-control", "info", "-v"
        ], stderr=subprocess.PIPE).decode('utf-8').rstrip()


def get_service():
    if platform.system() in ['Windows', 'win32']:
        return 'wazuh-agent'

    else:  # Linux, sunos5, darwin, aix...
        service = subprocess.check_output([
          f"{WAZUH_PATH}/bin/wazuh-control", "info", "-t"
        ], stderr=subprocess.PIPE).decode('utf-8').strip()

    return 'wazuh-manager' if service == 'server' else 'wazuh-agent'


_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
WAZUH_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')
ALERT_FILE_PATH = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
CLUSTER_LOGS_PATH = os.path.join(WAZUH_LOGS_PATH, 'cluster.log')

QUEUE_OSSEC_PATH = os.path.join(WAZUH_PATH, 'queue', 'ossec')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
CLUSTER_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'cluster')

WAZUH_SOCKETS = {
    'wazuh-agentd': [],
    'wazuh-analysisd': [os.path.join(QUEUE_OSSEC_PATH, 'analysis'),
                        os.path.join(QUEUE_OSSEC_PATH, 'queue')],
    'wazuh-authd': [os.path.join(QUEUE_OSSEC_PATH, 'auth')],
    'wazuh-execd': [os.path.join(QUEUE_OSSEC_PATH, 'com')],
    'wazuh-logcollector': [os.path.join(QUEUE_OSSEC_PATH, 'logcollector')],
    'wazuh-monitord': [os.path.join(QUEUE_OSSEC_PATH, 'monitor')],
    'wazuh-remoted': [os.path.join(QUEUE_OSSEC_PATH, 'request')],
    'wazuh-syscheckd': [os.path.join(QUEUE_OSSEC_PATH, 'syscheck')],
    'wazuh-db': [os.path.join(QUEUE_DB_PATH, 'wdb')],
    'wazuh-modulesd': [os.path.join(QUEUE_OSSEC_PATH, 'wmodules'),
                       os.path.join(QUEUE_OSSEC_PATH, 'download'),
                       os.path.join(QUEUE_OSSEC_PATH, 'control'),
                       os.path.join(QUEUE_OSSEC_PATH, 'krequest')],
    'wazuh-clusterd': [os.path.join(CLUSTER_SOCKET_PATH, 'c-internal.sock')]
}

# These sockets do not exist with default Wazuh configuration
WAZUH_OPTIONAL_SOCKETS = [
    os.path.join(QUEUE_OSSEC_PATH, 'krequest'),
    os.path.join(QUEUE_OSSEC_PATH, 'auth')
]


