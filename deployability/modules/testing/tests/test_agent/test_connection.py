from ..helpers import utils


def test_local_connection_status(agent_id):
    expected_status = 'connected'

    assert utils.check_agent_is_connected(agent_id)
    assert utils.get_agent_connection_status(agent_id) == expected_status, 'Agent not connected to manager.'


def test_server_connection_status(wazuh_api, agent_id):
    expected_status = 'active'
    agent_info = wazuh_api.get_agent(agent_id)

    assert agent_info.get('status') == expected_status, 'Agent not connected to manager.'
