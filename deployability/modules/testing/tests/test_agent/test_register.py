from ..helpers import utils
from ..helpers.constants import WAZUH_LOG, CLIENT_KEYS, KEY_REQ_AGENT


def test_register_logs():
    expected_log = KEY_REQ_AGENT

    assert utils.file_monitor(WAZUH_LOG, expected_log), "Register logs not found."


def test_client_keys():
    assert CLIENT_KEYS.exists(), 'client.keys file not found.'


def test_client_id():
    agent_id = utils.get_client_keys()[0].get('id')

    assert agent_id, 'Agent key not found in client.keys.'


def test_register_on_server(wazuh_api, agent_id):
    expected_status = ['active', 'pending', 'never connected']
    agent_info = wazuh_api.get_agent(agent_id)

    assert agent_info.get('status') in expected_status
