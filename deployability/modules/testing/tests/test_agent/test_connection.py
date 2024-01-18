from ..helpers import utils


def test_agent_connects_to_manager(wazuh_api):
    expected_status = "active"
    agent_id = utils.get_client_keys()[0].get('id')
    agent_info = wazuh_api.get_agent(agent_id)

    assert agent_info.get('status') == expected_status


def test_agent_connection_status():
    expected_status = "connected"
    agent_id = utils.get_client_keys()[0].get('id')

    assert utils.check_agent_is_connected(agent_id)
    assert utils.get_agent_connection_status(agent_id) == expected_status
