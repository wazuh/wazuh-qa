import pwd
import grp

from pathlib import Path


## --- Constants ---

# Paths
WAZUH_PATH = Path("/var", "ossec")
CONFIGURATION_PATH = Path(WAZUH_PATH, "etc")
BINARIES_PATHS = Path(WAZUH_PATH, "bin")
WAZUH_CONF = Path(CONFIGURATION_PATH, "ossec.conf")
WAZUH_CONTROL = Path(BINARIES_PATHS, "wazuh-control")

# Unix users and groups
WAZUH_USER = "wazuh"
WAZUH_GROUP = "wazuh"


## --- Tests ---

def test_wazuh_user():
    all_users = [x[0] for x in pwd.getpwall()]
    assert WAZUH_USER in all_users, "Wazuh user not found."


def test_wazuh_group():
    all_groups = [x[0] for x in grp.getgrall()]
    assert WAZUH_GROUP in all_groups, "Wazuh group not found."


def test_wazuh_configuration():
    assert CONFIGURATION_PATH.exists(), "Configuration directory not found."
    assert WAZUH_CONF.exists(), "Configuration file not found."


def test_wazuh_control():
    assert BINARIES_PATHS.exists(), "Binaries directory not found."
    assert WAZUH_CONTROL.exists(), "Wazuh control binary not found."
