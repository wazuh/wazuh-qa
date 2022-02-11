import pytest
from wazuh_testing import global_parameters


def test_agent_connection(get_report):
    """Check that:
        - Agents are connected everytime 
        - N tcp connections is equal to n of active agents
    """
    report = global_parameters.report
    wazuh_agentd_report = report['agents']['wazuh-agentd']

    assert wazuh_agentd_report['ever_disconnected'] == 0, "Some agents has disconnected"
    assert wazuh_agentd_report['ever_pending'] == 0, "Some agents has change to pending status"
    assert wazuh_agentd_report['begin_status']['connected'] == wazuh_agentd_report['end_status']['connected'] == report['metadata']['n_agents'], "Some agents statuses have not been gathered correctly"
