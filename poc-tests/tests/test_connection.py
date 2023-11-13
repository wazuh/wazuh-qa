from helpers import constants, utils


# Actual running service.
service = utils.get_service()


def test_agent_connects_to_manager():
    manager_log = "New wazuh agent connected"
    agent_log = "Connected to the server"

    expected_message = agent_log if service == "agent" else manager_log
    log_file = constants.WAZUH_LOG if service == "agent" else constants.ALERTS_JSON

    assert utils.file_monitor(log_file, expected_message)


def test_agent_connection_status():
    expected_status = "connected" if service == "agent" else "Active"

    assert utils.get_agent_connection_status("001") == expected_status
