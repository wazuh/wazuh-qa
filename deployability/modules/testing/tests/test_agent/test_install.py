import grp
import pwd


from ..helpers import actions
from ..helpers import constants, utils


def test_installation():
    scan_directory = "/var"
    initial_scan = actions.scan_directory(scan_directory)
    print("Initial scan:")
    print(initial_scan)
    
    actions.checkfiles('linux')
    #actions.install_wazuh_agent('linux', '4.7.2', '1', 'packages', '4.x', '127.0.0.1', 'deb', 'amd64')
    actions.uninstall_wazuh_agent('linux', '4.7.2', '1','deb')
    
    second_scan = actions.scan_directory(scan_directory)
    print("\nPost scan:")
    print(second_scan)
    
    changes = actions.compare_directories(initial_scan, second_scan)
    print("\nDetected changes:")
    print(changes)

    
""" 
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


def test_wazuh_service(component):
    expected_service = component
    assert utils.get_service() == expected_service, f"Installed service is not the expected."


def test_wazuh_daemons():
    actual_daemons = utils.get_daemons_status()
    expected_daemons = constants.AGENT_DAEMONS

    for daemon in expected_daemons:
        assert daemon in actual_daemons.keys(), f"{daemon} not found."
"""