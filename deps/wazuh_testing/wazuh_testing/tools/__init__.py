# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

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
    with open("/etc/ossec-init.conf") as ossec_init:
        WAZUH_PATH = os.path.join(
            [item.rstrip().replace("DIRECTORY=", "").replace("\"", "")
            for item in ossec_init.readlines() if "DIRECTORY" in item][0])
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_API_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'api.yaml')
    WAZUH_SECURITY_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'security', 'security.yaml')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    API_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.log')
    if sys.platform == 'darwin':
        PREFIX = os.path.join('/', 'private', 'var', 'root') 
        GEN_OSSEC = None
    else:
        PREFIX = os.sep
        GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')
    try:
        import grp
        import pwd

        OSSEC_UID = pwd.getpwnam("ossec").pw_uid
        OSSEC_GID = grp.getgrnam("ossec").gr_gid
    except (ImportError, KeyError, ModuleNotFoundError):
        pass

if sys.platform == 'darwin' or sys.platform == 'win32' or sys.platform == 'sunos5':
    WAZUH_SERVICE = 'wazuh.agent'
else:
    try:
        with open(os.path.join(WAZUH_PATH, 'etc/ossec-init.conf'), 'r') as f:
            type_ = None
            for line in f.readlines():
                if 'TYPE' in line:
                    type_ = line.split('"')[1]
            WAZUH_SERVICE = 'wazuh-manager' if type_ == 'server' else 'wazuh-agent'
    except FileNotFoundError:
        pass

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
WAZUH_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')
ALERT_FILE_PATH = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
CLUSTER_LOGS_PATH = os.path.join(WAZUH_LOGS_PATH, 'cluster.log')

QUEUE_OSSEC_PATH = os.path.join(WAZUH_PATH, 'queue', 'ossec')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
CLUSTER_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'cluster')

WAZUH_SOCKETS = {
    'ossec-agentd'   : [],
    'ossec-analysisd': [os.path.join(QUEUE_OSSEC_PATH, 'analysis'),
                        os.path.join(QUEUE_OSSEC_PATH, 'queue')],
    'ossec-authd': [os.path.join(QUEUE_OSSEC_PATH, 'auth')],
    'ossec-execd': [os.path.join(QUEUE_OSSEC_PATH, 'com')],
    'ossec-logcollector': [os.path.join(QUEUE_OSSEC_PATH, 'logcollector')],
    'ossec-monitord': [os.path.join(QUEUE_OSSEC_PATH, 'monitor')],
    'ossec-remoted': [os.path.join(QUEUE_OSSEC_PATH, 'request')],
    'ossec-syscheckd': [os.path.join(QUEUE_OSSEC_PATH, 'syscheck')],
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
