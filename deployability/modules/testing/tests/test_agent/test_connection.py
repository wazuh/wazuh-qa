from ..helpers import utils
from ..helpers.constants import CONNECTION_AGENT, WAZUH_LOG


def test_agent_connects_to_manager(component):
    expected_log = CONNECTION_AGENT
    log_file = WAZUH_LOG
    assert utils.file_monitor(log_file, expected_log)


def test_agent_connection_status():
    expected_status = "connected"

    assert utils.check_agent_is_connected("001")
    assert utils.get_agent_connection_status("001") == expected_status
