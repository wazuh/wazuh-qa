from wazuh_testing.tools.services import check_if_process_is_running


def check_if_modulesd_is_running():
    """Check if modulesd daemon is running"""
    assert check_if_process_is_running('wazuh-modulesd'), 'wazuh-modulesd is not running. It may have crashed'


def check_if_daemons_are_running(daemons):
    """Check if daemons are running"""
    for daemon in daemons:
        assert check_if_process_is_running(daemon), f"{daemon} is not running. It may have crashed"
