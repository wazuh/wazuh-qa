from pathlib import Path


# --- Paths ---
WAZUH_ROOT = Path("/var", "ossec")
# Configuration paths
CONFIGURATIONS_DIR = Path(WAZUH_ROOT, "etc")
WAZUH_CONF = Path(CONFIGURATIONS_DIR, "ossec.conf")
CLIENT_KEYS = Path(CONFIGURATIONS_DIR, "client.keys")
# Binaries paths
BINARIES_DIR = Path(WAZUH_ROOT, "bin")
WAZUH_CONTROL = Path(BINARIES_DIR, "wazuh-control")
AGENT_CONTROL = Path(BINARIES_DIR, "agent_control")
# Logs paths
LOGS_DIR = Path(WAZUH_ROOT, "logs")
WAZUH_LOG = Path(LOGS_DIR, "ossec.log")
ALERTS_DIR = Path(LOGS_DIR, "alerts")
ALERTS_JSON = Path(ALERTS_DIR, "alerts.json")
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
AGENT_CONNECTED = "New wazuh agent connected"
CONNECTED_TO_SERVER = "Connected to the server"
AGENT_REGISTERED = "Agent successfully registered"
REQUESTING_KEY = "Requesting a key from server"
RECEIVE_KEY_REQUEST = "Received request for a new agent"
