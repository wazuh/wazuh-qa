import pytest


def test_agent_connection(get_report):
    wazuh_target_report_agentd = get_report["agents"]['wazuh-agentd']
    wazuh_target_report_remoted = get_report["managers"]['wazuh-remoted']

    # Ensure TCP sessions is equal to the number of agent
    assert wazuh_target_report_remoted['min_tcp_sessions'] == get_report['metadata']['n_agents']

    # Ensure all agent status is connected during all the environment uptime
    assert wazuh_target_report_agentd['ever_disconnected'] == 0, "Some agents has disconnected"

    assert wazuh_target_report_agentd['ever_pending'] == 0, "Some agents has change to pending status"

    assert wazuh_target_report_agentd['begin_status']['connected'] == \
           wazuh_target_report_agentd['end_status']['connected'] == \
           get_report['metadata']['n_agents'], "Some agents statuses have not been gathered correctly"
