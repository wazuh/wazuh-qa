import grp
import pwd

from ..helpers import constants, utils, check_files


def test_files_permissions():

    missing_names = []
    extra_names = []
    different_names = []
    # Get data
    static_items, dynamic_items = check_files.get_template_items('agent')
    current_items = check_files.get_current_items()
    # HARDCODED: Always ignore /var/ossec/api/node_modules/
    current_items, _ = check_files.cut_items(current_items)
    static_items, _ = check_files.cut_items(static_items, ['/var/ossec/wodles/aws'])
    dynamic_items, _ = check_files.cut_items(dynamic_items)


    static_names = static_items.keys()
    dynamic_names = dynamic_items.keys()
    current_names = current_items.keys()


    # Missing files/directories
    missing_names = set(static_names) - set(current_names)

    # Extra files/directories
    extra_names_tmp = set(current_names) - set(static_names)
    check_extra_names = []
    for extra_name in extra_names_tmp:
        if extra_name in dynamic_names:
            check_extra_names.append(extra_name)
        else:
            extra_names.append(extra_name)

    # Different files/directories
    different_items = {}
    # Static
    for item in static_items:
        if item not in missing_names and static_items[item] != current_items[item]:
            different_names.append(item)
            different_items[item] = static_items[item]
    # Dynamic
    for check_extra_name in check_extra_names:
        if dynamic_items[check_extra_name] != current_items[check_extra_name]:
            different_names.append(check_extra_name)
            different_items[check_extra_name] = dynamic_items[check_extra_name]

    # print("Missing files/directories:" + str(missing_names))
    # print("Extra files/directories:" + str(extra_names))
    for different_name in different_names:
        print('\nDifferent file:', different_name)
        print('Actual file:', current_items[different_name])
        print('Expected file:', different_items[different_name])
    # print("Different files/directories:" + str(different_items))



# The test receives the environment with wazuh-agent installed and started.

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
