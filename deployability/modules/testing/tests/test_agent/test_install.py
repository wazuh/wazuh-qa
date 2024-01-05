import grp
import os
import pwd

from ..helpers import constants, utils



def test_wazuh_user():
    all_users = [x[0] for x in pwd.getpwall()]
    assert constants.WAZUH_USER in all_users, "Wazuh user not found."


def test_wazuh_group():
    all_groups = [x[0] for x in grp.getgrall()]
    assert constants.WAZUH_GROUP in all_groups, "Wazuh group not found."

# Check files permissions checkfiles close-world

def test_files_permissions():
    for file in constants.FILES:
        assert os.stat(file).st_mode == constants.FILE_PERMISSIONS, f"{file} permissions are not the expected."

# Check start


def test_daemons_started():
    actual_daemons = utils.get_daemons_status()
    expected_daemons = constants.AGENT_DAEMONS

    for daemon in expected_daemons:
        assert daemon in actual_daemons.keys(), f"{daemon} not found."
