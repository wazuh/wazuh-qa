import pytest

from helpers import utils
from helpers.constants import WAZUH_LOG, CLIENT_KEYS, REQUESTING_KEY, RECEIVE_KEY_REQUEST


# Actual running service.
service = utils.get_service()


if service == "manager":
    # Test only for wazuh-manager, this could be replace by a pytest mark.
    def test_agent_is_registered_in_server():
        agents = utils.get_registered_agents()
        agent_found = [a for a in agents if a.get('ID') == '001']
        assert agent_found, "Agent is not registered."


def test_register_logs_were_generated():
    expected_log = REQUESTING_KEY if service == "agent" else RECEIVE_KEY_REQUEST

    assert utils.file_monitor(WAZUH_LOG, expected_log), "Register logs not found."


def test_client_keys_file_exists():
    assert CLIENT_KEYS.exists(), 'client.keys file not found.'


def test_agent_key_is_in_client_keys():
    assert '001' in CLIENT_KEYS.read_text(), 'Agent key not found in client.keys.'
