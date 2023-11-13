from helpers import constants, utils
from helpers.constants import AGENT_CONNECTED, CONNECTED_TO_SERVER


# Actual running service.
service = utils.get_service()


def test_agent_connects_to_manager():
    expected_log = AGENT_CONNECTED if service == "agent" else CONNECTED_TO_SERVER
    log_file = constants.WAZUH_LOG if service == "agent" else constants.ALERTS_JSON

    assert utils.file_monitor(log_file, expected_log)


def test_agent_connection_status():
    expected_status = "connected" if service == "agent" else "Active"

    assert utils.get_agent_connection_status("001") == expected_status
