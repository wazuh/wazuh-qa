import pwd
import grp

from helpers import constants, utils


def test_wazuh_user():
    all_users = [x[0] for x in pwd.getpwall()]
    assert constants.WAZUH_USER in all_users, "Wazuh user not found."


def test_wazuh_group():
    all_groups = [x[0] for x in grp.getgrall()]
    assert constants.WAZUH_GROUP in all_groups, "Wazuh group not found."


def test_wazuh_configuration():
    assert constants.CONFIGURATIONS_DIR.exists(), "Configuration directory not found."
    assert constants.WAZUH_CONF.exists(), "Configuration file not found."


def test_wazuh_control():
    assert constants.BINARIES_DIR.exists(), "Binaries directory not found."
    assert constants.WAZUH_CONTROL.exists(), "Wazuh control binary not found."


def test_wazuh_daemons():
    actual_daemons = utils.get_daemons_status()

    if utils.get_service == "agent":
        expected_daemons = constants.AGENT_DAEMONS
    else:
        expected_daemons = constants.MANAGER_DAEMONS

    for daemon in expected_daemons:
        assert daemon in actual_daemons, f"{daemon} not found."
