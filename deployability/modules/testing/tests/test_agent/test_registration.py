from ..helpers import utils
from ..helpers.constants import CLIENT_KEYS


def test_client_keys_file():
    assert CLIENT_KEYS.exists(), 'client.keys file not found.'


def test_agent_registered(agent_info: dict):
    expected_status = ['active', 'pending', 'never connected']
    assert agent_info.get('status') in expected_status


def test_client_id_local():
    agent_id = utils.get_client_keys()[0].get('id')
    assert agent_id, 'Agent key not found in client.keys.'
