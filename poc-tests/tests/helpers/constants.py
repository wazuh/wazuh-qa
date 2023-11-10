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