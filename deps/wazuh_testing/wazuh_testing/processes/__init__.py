from wazuh_testing.tools.services import check_if_process_is_running


def check_if_modulesd_is_running():
    """Check if modulesd daemon is running"""
    assert check_if_process_is_running('wazuh-modulesd'), 'wazuh-modulesd is not running!'
