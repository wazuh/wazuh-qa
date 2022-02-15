import pytest


def test_agent_connection(get_report):
    report = get_report
    wazuh_agentd_report = report['agents']['wazuh-agentd']

    assert wazuh_agentd_report['ever_disconnected'] == 0, "Some agents has disconnected"
    assert wazuh_agentd_report['ever_pending'] == 0, "Some agents has change to pending status"
    assert wazuh_agentd_report['begin_status']['connected'] == \
           wazuh_agentd_report['end_status']['connected'] == \
           report['metadata']['n_agents'], "Some agents statuses have not been gathered correctly"
