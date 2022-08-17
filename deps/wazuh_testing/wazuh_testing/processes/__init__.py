from wazuh_testing.tools.services import check_if_process_is_running


def check_if_modulesd_is_running():
    """Check if modulesd daemon is running"""
    assert check_if_process_is_running('wazuh-modulesd'), 'wazuh-modulesd is not running. It may have crashed'


def check_if_deamon_is_running(daemon):
    """Check if the specified daemon is running"""
    assert check_if_process_is_running(daemon), f"{daemon} is not running. It may have crashed"


def check_if_deamon_is_not_running(daemon):
    """Check if the specified daemon is running"""
    assert check_if_process_is_running(daemon) == False, f"{daemon} is running. It may have crashed"
