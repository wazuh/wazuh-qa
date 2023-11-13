import pytest

from helpers import constants, utils


def test_agent_is_registered_in_server():
    if utils.get_service() == "agent":
        pytest.skip("Skipping test for agent installations.")
    registered_agents = utils.get_registered_agents()
    assert [a for a in registered_agents if a.get('ID') == '001'], "Agent is not registered."


def test_register_logs_were_generated():
    if utils.get_service() == "agent":
        expected_log = "Requesting a key from server"
    else:
        expected_log = "Received request for a new agent"

    log_found = utils.file_monitor(constants.WAZUH_LOG, expected_log)
    assert log_found, "Register logs were not generated."


def test_client_keys_file_exists():
    assert constants.CLIENT_KEYS.exists(), 'client.keys file not found.'


def test_agent_key_is_in_client_keys():
    assert '001' in constants.CLIENT_KEYS.read_text(
    ), 'Agent key not found in client.keys file.'
