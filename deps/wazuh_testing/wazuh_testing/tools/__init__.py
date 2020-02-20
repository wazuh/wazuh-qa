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

elif sys.platform == 'darwin':
    WAZUH_PATH = os.path.join('/', 'Library', 'Ossec')
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    PREFIX = os.path.join('/', 'private', 'var', 'root')
    GEN_OSSEC = None

else:
    WAZUH_PATH = os.path.join('/', 'var', 'ossec')
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')
    PREFIX = os.sep

if sys.platform == 'darwin' or sys.platform == 'win32' or sys.platform == 'sunos5':
    WAZUH_SERVICE = 'wazuh.agent'
else:
    with open(os.path.join(WAZUH_PATH, 'etc/ossec-init.conf'), 'r') as f:
        type_ = None
        for line in f.readlines():
            if 'TYPE' in line:
                type_ = line.split('"')[1]
        WAZUH_SERVICE = 'wazuh-manager' if type_ == 'server' else 'wazuh-agent'

_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
WAZUH_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')
ALERT_FILE_PATH = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')

QUEUE_OSSEC_PATH = os.path.join(WAZUH_PATH, 'queue', 'ossec')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')

WAZUH_SOCKETS = {
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
                       os.path.join(QUEUE_OSSEC_PATH, 'control')]
}
