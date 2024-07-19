# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from pathlib import Path


# --- Paths ---
WAZUH_ROOT = Path("/var", "ossec")
# Configuration paths
CONFIGURATIONS_DIR = Path(WAZUH_ROOT, "etc")
WAZUH_CONF = Path(CONFIGURATIONS_DIR, "ossec.conf")
CLIENT_KEYS = Path(CONFIGURATIONS_DIR, "client.keys")

WINDOWS_ROOT_DIR = Path("C:", "Program Files (x86)", "ossec-agent")
WINDOWS_CONFIGURATIONS_DIR = Path(WINDOWS_ROOT_DIR, "etc")
WAZUH_WINDOWS_CONF  = Path(WINDOWS_ROOT_DIR, "ossec.conf")
WINDOWS_CLIENT_KEYS = Path(WINDOWS_ROOT_DIR, "client.keys")
WINDOWS_VERSION = Path(WINDOWS_ROOT_DIR, "VERSION")
WINDOWS_REVISION = Path(WINDOWS_ROOT_DIR, "REVISION")

MACOS_ROOT_DIR = Path("/Library", "Ossec")
MACOS_CONFIGURATIONS_DIR = Path(MACOS_ROOT_DIR, "etc")
WAZUH_MACOS_CONF  = Path(MACOS_CONFIGURATIONS_DIR, "ossec.conf")
MACOS_CLIENT_KEYS = Path(MACOS_CONFIGURATIONS_DIR, "client.keys")
MACOS_VERSION = Path(MACOS_ROOT_DIR, "VERSION")
MACOS_REVISION = Path(MACOS_ROOT_DIR, "REVISION")


# Binaries paths
BINARIES_DIR = Path(WAZUH_ROOT, "bin")
WAZUH_CONTROL = Path(BINARIES_DIR, "wazuh-control")
AGENT_CONTROL = Path(BINARIES_DIR, "agent_control")
CLUSTER_CONTROL = Path(BINARIES_DIR, "cluster_control")

MACOS_BINARIES_DIR = Path(MACOS_ROOT_DIR, "bin")
MACOS_WAZUH_CONTROL = Path(MACOS_BINARIES_DIR, "wazuh-control")

# Logs paths
LOGS_DIR = Path(WAZUH_ROOT, "logs")
WAZUH_LOG = Path(LOGS_DIR, "ossec.log")
ALERTS_DIR = Path(LOGS_DIR, "alerts")
ALERTS_JSON = Path(ALERTS_DIR, "alerts.json")

MACOS_LOGS_DIR = Path(MACOS_ROOT_DIR, "logs")
WAZUH_MACOS_LOG = Path(MACOS_LOGS_DIR, "ossec.log")
MACOS_ALERTS_DIR = Path(MACOS_LOGS_DIR, "alerts")
MACOS_ALERTS_JSON = Path(MACOS_ALERTS_DIR, "alerts.json")

# Daemons running paths
DAEMONS_DIR = Path(WAZUH_ROOT, "var", "run")
AGENTD_STATE = Path(DAEMONS_DIR, "wazuh-agentd.state")

# --- Users & Groups ---
WAZUH_USER = "wazuh"
WAZUH_GROUP = "wazuh"

# --- Daemons ---
AGENTD = 'wazuh-agentd'
AGENTLESSD = 'wazuh-agentlessd'
ANALYSISDD = 'wazuh-analysisd'
APID = 'wazuh-apid'
CLUSTERD = 'wazuh-clusterd'
CSYSLOGD = 'wazuh-csyslogd'
EXECD = 'wazuh-execd'
INTEGRATORD = 'wazuh-integratord'
MAILD = 'wazuh-maild'
MODULESD = 'wazuh-modulesd'
MONITORD = 'wazuh-monitord'
LOGCOLLECTORD = 'wazuh-logcollector'
REMOTED = 'wazuh-remoted'
SYSCHECKD = 'wazuh-syscheckd'
WAZUH_DBD = 'wazuh-db'
# Daemons lists
AGENT_DAEMONS = [AGENTD,
                 EXECD,
                 MODULESD,
                 LOGCOLLECTORD,
                 SYSCHECKD]
MANAGER_DAEMONS = [AGENTLESSD,
                   ANALYSISDD,
                   APID,
                   CLUSTERD,
                   CSYSLOGD,
                   EXECD,
                   INTEGRATORD,
                   LOGCOLLECTORD,
                   MAILD,
                   MODULESD,
                   MONITORD,
                   REMOTED,
                   SYSCHECKD,
                   WAZUH_DBD]

# --- Log messages ---
CONNECTION_SERVER = "New wazuh agent connected"
CONNECTION_AGENT = "Connected to the server"
KEY_REQ_AGENT = "Requesting a key from server"
KEY_REQ_SERVER = "Received request for a new agent"
RELEASING_RESOURCES = "Shutdown received. Releasing resources"
DELETING_RESPONSES = "Shutdown received. Deleting responses"
STARTED = 'INFO: Started'
