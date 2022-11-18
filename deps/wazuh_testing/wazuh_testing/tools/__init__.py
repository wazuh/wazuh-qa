# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import platform
import subprocess
import sys


if sys.platform == 'win32':
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    WAZUH_CONF = os.path.join(WAZUH_PATH, 'ossec.conf')
    WAZUH_LOCAL_INTERNAL_OPTIONS = os.path.join(WAZUH_PATH, 'local_internal_options.conf')
    WAZUH_SOURCES = os.path.join('/', 'wazuh')
    AGENT_CONF = os.path.join(WAZUH_PATH, 'shared', 'agent.conf')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'ossec.log')
    CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'client.keys')
    PREFIX = os.path.join('c:', os.sep)
    GEN_OSSEC = None
    WAZUH_API_CONF = None
    WAZUH_SECURITY_CONF = None
    API_LOG_FILE_PATH = None
    API_JSON_LOG_FILE_PATH = None
    API_LOG_FOLDER = None
    AGENT_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'wazuh-agent.state')
    LOGCOLLECTOR_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'wazuh-logcollector.state')
    REMOTE_STATISTICS_FILE = None
    ANALYSIS_STATISTICS_FILE = None
    UPGRADE_PATH = os.path.join(WAZUH_PATH, 'upgrade')
    AGENT_AUTH_BINARY_PATH = os.path.join(WAZUH_PATH, 'agent-auth.exe')
    ANALYSISD_BINARY_PATH = None
    HOSTS_FILE_PATH = os.path.join("C:", os.sep, "Windows", "System32", "drivers", "etc", "hosts")
    GLOBAL_DB_PATH = None
    WAZUH_UNIX_USER = 'wazuh'
    WAZUH_UNIX_GROUP = 'wazuh'
    GLOBAL_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db', 'global.db')
    ACTIVE_RESPONSE_BINARY_PATH = os.path.join(WAZUH_PATH, 'active-response', 'bin')
else:
    WAZUH_SOURCES = os.path.join('/', 'wazuh')

    WAZUH_UNIX_USER = 'wazuh'
    WAZUH_UNIX_GROUP = 'wazuh'

    if sys.platform == 'darwin':
        WAZUH_PATH = os.path.join("/", "Library", "Ossec")
        PREFIX = os.path.join('/', 'private', 'var', 'root')
        GEN_OSSEC = None
    else:
        WAZUH_PATH = os.path.join("/", "var", "ossec")
        GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')
        PREFIX = os.sep

    WAZUH_CONF_RELATIVE = os.path.join('etc', 'ossec.conf')
    WAZUH_LOCAL_INTERNAL_OPTIONS = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    WAZUH_CONF = os.path.join(WAZUH_PATH, WAZUH_CONF_RELATIVE)
    AGENT_CONF = os.path.join(WAZUH_PATH, 'etc', 'shared', 'agent.conf')
    WAZUH_API_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'api.yaml')
    WAZUH_SECURITY_CONF = os.path.join(WAZUH_PATH, 'api', 'configuration', 'security', 'security.yaml')
    LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
    API_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.log')
    API_JSON_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.json')
    API_LOG_FOLDER = os.path.join(WAZUH_PATH, 'logs', 'api')
    ARCHIVES_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'archives', 'archives.log')
    AGENT_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'var', 'run', 'wazuh-agentd.state')
    LOGCOLLECTOR_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'var', 'run', 'wazuh-logcollector.state')
    LOGCOLLECTOR_FILE_STATUS_PATH = os.path.join(WAZUH_PATH, 'queue', 'logcollector', 'file_status.json')
    REMOTE_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'var', 'run', 'wazuh-remoted.state')
    ANALYSIS_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'var', 'run', 'wazuh-analysisd.state')
    UPGRADE_PATH = os.path.join(WAZUH_PATH, 'var', 'upgrade')
    PYTHON_PATH = os.path.join(WAZUH_PATH, 'framework', 'python')
    AGENT_AUTH_BINARY_PATH = os.path.join(WAZUH_PATH, 'bin', 'agent-auth')
    ANALYSISD_BINARY_PATH = os.path.join(WAZUH_PATH, 'bin', 'wazuh-analysisd')
    ACTIVE_RESPONSE_BINARY_PATH = os.path.join(WAZUH_PATH, 'active-response', 'bin')

    if sys.platform == 'sunos5':
        HOSTS_FILE_PATH = os.path.join('/', 'etc', 'inet', 'hosts')
    else:
        HOSTS_FILE_PATH = os.path.join('/', 'etc', 'hosts')
    GLOBAL_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db', 'global.db')

    try:
        import grp
        import pwd

        WAZUH_UID = pwd.getpwnam(WAZUH_UNIX_USER).pw_uid
        WAZUH_GID = grp.getgrnam(WAZUH_UNIX_GROUP).gr_gid
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


_data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'data')

CUSTOM_RULES_PATH = os.path.join(WAZUH_PATH, 'etc', 'rules')
LOCAL_RULES_PATH = os.path.join(CUSTOM_RULES_PATH, 'local_rules.xml')
LOCAL_DECODERS_PATH = os.path.join(WAZUH_PATH, 'etc', 'decoders', 'local_decoder.xml')

SERVER_KEY_PATH = os.path.join(WAZUH_PATH, 'etc', 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, 'etc', 'manager.cert')

CLIENT_CUSTOM_KEYS_PATH = os.path.join(_data_path, 'sslmanager.key')
CLIENT_CUSTOM_CERT_PATH = os.path.join(_data_path, 'sslmanager.cert')

WAZUH_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')
ALERT_FILE_PATH = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.json')
ALERT_LOGS_PATH = os.path.join(WAZUH_LOGS_PATH, 'alerts', 'alerts.log')
CLUSTER_LOGS_PATH = os.path.join(WAZUH_LOGS_PATH, 'cluster.log')
QUEUE_SOCKETS_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets')
QUEUE_ALERTS_PATH = os.path.join(WAZUH_PATH, 'queue', 'alerts')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
CLUSTER_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'cluster')


ANALYSISD_ANALISIS_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'analysis')
ANALYSISD_QUEUE_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'queue')
AUTHD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'auth')
EXECD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'com')
LOGCOLLECTOR_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logcollector')
LOGTEST_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logtest')
MONITORD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'monitor')
REMOTED_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'remote')
SYSCHECKD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'syscheck')
WAZUH_DB_SOCKET_PATH = os.path.join(QUEUE_DB_PATH, 'wdb')
MODULESD_WMODULES_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'wmodules')
MODULESD_DOWNLOAD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'download')
MODULESD_CONTROL_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'control')
MODULESD_KREQUEST_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'krequest')
MODULESD_C_INTERNAL_SOCKET_PATH = os.path.join(CLUSTER_SOCKET_PATH, 'c-internal.sock')
ACTIVE_RESPONSE_SOCKET_PATH = os.path.join(QUEUE_ALERTS_PATH, 'ar')

WAZUH_SOCKETS = {
    'wazuh-agentd': [],
    'wazuh-apid': [],
    'wazuh-agentlessd': [],
    'wazuh-csyslogd': [],
    'wazuh-analysisd': [
                        ANALYSISD_ANALISIS_SOCKET_PATH,
                        ANALYSISD_QUEUE_SOCKET_PATH
                       ],
    'wazuh-authd': [AUTHD_SOCKET_PATH],
    'wazuh-execd': [EXECD_SOCKET_PATH],
    'wazuh-logcollector': [LOGCOLLECTOR_SOCKET_PATH],
    'wazuh-monitord': [MONITORD_SOCKET_PATH],
    'wazuh-remoted': [REMOTED_SOCKET_PATH],
    'wazuh-maild': [],
    'wazuh-syscheckd': [SYSCHECKD_SOCKET_PATH],
    'wazuh-db': [WAZUH_DB_SOCKET_PATH],
    'wazuh-modulesd': [
                        MODULESD_WMODULES_SOCKET_PATH,
                        MODULESD_DOWNLOAD_SOCKET_PATH,
                        MODULESD_CONTROL_SOCKET_PATH,
                        MODULESD_KREQUEST_SOCKET_PATH
                      ],
    'wazuh-clusterd': [MODULESD_C_INTERNAL_SOCKET_PATH]
}

# These sockets do not exist with default Wazuh configuration
WAZUH_OPTIONAL_SOCKETS = [
    MODULESD_KREQUEST_SOCKET_PATH,
    AUTHD_SOCKET_PATH
]

# Wazuh daemons
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


ALL_MANAGER_DAEMONS = [LOGCOLLECTOR_DAEMON, AGENTLESS_DAEMON, CSYSLOG_DAEMON, REMOTE_DAEMON, ANALYSISD_DAEMON,
                       API_DAEMON, MAIL_DAEMON, SYSCHECK_DAEMON, EXEC_DAEMON, MODULES_DAEMON, CLUSTER_DAEMON,
                       INTEGRATOR_DAEMON, MONITOR_DAEMON, DB_DAEMON]
ALL_AGENT_DAEMONS = [AGENT_DAEMON, EXEC_DAEMON, LOGCOLLECTOR_DAEMON, SYSCHECK_DAEMON, MODULES_DAEMON]
API_DAEMONS_REQUIREMENTS = [API_DAEMON, MODULES_DAEMON, ANALYSISD_DAEMON, EXEC_DAEMON, DB_DAEMON, REMOTE_DAEMON]


DISABLE_MONITORD_ROTATE_LOG_OPTION = {'monitord.rotate_log': '0'}
ANALYSISD_LOCAL_INTERNAL_OPTIONS = {'analysisd.debug': '2'}.update(DISABLE_MONITORD_ROTATE_LOG_OPTION)
AGENTD_LOCAL_INTERNAL_OPTIONS = {'agent.debug': '2', 'execd': '2'}.update(DISABLE_MONITORD_ROTATE_LOG_OPTION)
GCLOUD_LOCAL_INTERNAL_OPTIONS = {'analysisd.debug': '2',
                                 'wazuh_modules.debug': '2'}.update(DISABLE_MONITORD_ROTATE_LOG_OPTION)
LOGTEST_LOCAL_INTERNAL_OPTIONS = {'analysisd.debug': '2'}
REMOTED_LOCAL_INTERNAL_OPTIONS = {'remoted.debug': '2', 'wazuh_database.interval': '2', 'wazuh_db.commit_time': '2',
                                  'wazuh_db.commit_time_max': '3'}.update(DISABLE_MONITORD_ROTATE_LOG_OPTION)
VD_LOCAL_INTERNAL_OPTIONS = {'wazuh_modules.debug': '2'}.update(DISABLE_MONITORD_ROTATE_LOG_OPTION)
WPK_LOCAL_INTERNAL_OPTIONS = {'wazuh_modules.debug': '2'}
