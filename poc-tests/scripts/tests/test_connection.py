from helpers import utils
from helpers.constants import CONNECTION_SERVER, CONNECTION_AGENT, WAZUH_LOG, ALERTS_JSON


# Actual running service.
service = utils.get_service()


def test_agent_connects_to_manager():
    expected_log = CONNECTION_AGENT if service == "agent" else CONNECTION_SERVER
    log_file = WAZUH_LOG if service == "agent" else ALERTS_JSON

    assert utils.file_monitor(log_file, expected_log)


def test_agent_connection_status():
    expected_status = "connected" if service == "agent" else "Active"

    assert utils.get_agent_connection_status("001") == expected_status
