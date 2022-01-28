import pytest
from wazuh_testing import global_parameters


def test_remoted_error(get_report):
    """Check that:
        - Agents are connected everytime 
        - N tcp connections is equal to n of active agents
    """
    report = global_parameters.report
    wazuh_agentd_report = report['agents']['wazuh-agentd']

    assert wazuh_agentd_report['ever_disconnected'] == wazuh_agentd_report['ever_pending'] == 0
    assert wazuh_agentd_report['begin_status'] == wazuh_agentd_report['end_status'] == report['metadata']['n_agents']
