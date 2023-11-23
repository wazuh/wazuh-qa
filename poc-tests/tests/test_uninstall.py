import grp
import os
import pwd

from helpers import constants, utils


def test_wazuh_user():
    all_users = [x[0] for x in pwd.getpwall()]
    assert constants.WAZUH_USER not in all_users, "Wazuh user found."


def test_wazuh_group():
    all_groups = [x[0] for x in grp.getgrall()]
    assert constants.WAZUH_GROUP not in all_groups, "Wazuh group found."


def test_wazuh_configuration_dir():
    assert not constants.CONFIGURATIONS_DIR.exists(), "Configuration directory found."


def test_wazuh_configuration():
    assert not constants.WAZUH_CONF.exists(), "Configuration file found."


def test_wazuh_binaries_dir():
    assert not constants.BINARIES_DIR.exists(), "Binaries directory found."


def test_wazuh_control():
    assert not constants.WAZUH_CONTROL.exists(), "Wazuh control binary found."
