import pytest


def test_agent_connection(get_report):
    wazuh_target_report_agentd = get_report["agents"]['wazuh-agentd']
    wazuh_target_report_remoted = get_report["managers"]['wazuh-remoted']

    error_messages = []
    # Ensure TCP sessions is equal to the number of agent
    if not wazuh_target_report_remoted['min_tcp_sessions'] == get_report['metadata']['n_agents']:
        error_messages += ["TCP sessions are not the same as the number of agents"]

    # Ensure all agent status is connected during all the environment uptime
    if not wazuh_target_report_agentd['ever_disconnected'] == 0:
        error_messages += ["Some agents have disconnected"]

    if not wazuh_target_report_agentd['ever_pending'] == 0:
        error_messages += ["Some agents have change to pending status"]

    if not wazuh_target_report_agentd['begin_status']['connected'] == \
       wazuh_target_report_agentd['end_status']['connected'] == \
       get_report['metadata']['n_agents']:

        error_messages += ["Some agents statuses have not been gathered correctly"]

    assert not error_messages, f"Some agent connection errors have been detected {error_messages}"
