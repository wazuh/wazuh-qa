from pathlib import Path


# Paths
WAZUH_ROOT = Path("/var", "ossec")
CONFIGURATIONS_DIR = Path(WAZUH_ROOT, "etc")
BINARIES_DIR = Path(WAZUH_ROOT, "bin")
WAZUH_CONF = Path(CONFIGURATIONS_DIR, "ossec.conf")
WAZUH_CONTROL = Path(BINARIES_DIR, "wazuh-control")

# Unix users and groups
WAZUH_USER = "wazuh"
WAZUH_GROUP = "wazuh"

# Services
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

AGENT_SERVICES = [AGENTD,
                  EXECD,
                  MODULESD,
                  LOGCOLLECTORD,
                  SYSCHECKD]

MANAGER_SERVICES = [AGENTLESSD,
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
