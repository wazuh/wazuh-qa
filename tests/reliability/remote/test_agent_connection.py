import pytest
from wazuh_testing import global_parameters


target = ['agents']


@pytest.mark.parametrize('target', target)
def test_agent_connection(get_report, target):
    wazuh_target_report = get_report[target]['wazuh-agentd']

    assert wazuh_target_report['ever_disconnected'] == 0, "Some agents has disconnected"

    assert wazuh_target_report['ever_pending'] == 0, "Some agents has change to pending status"

    assert wazuh_target_report['begin_status']['connected'] == \
           wazuh_target_report['end_status']['connected'] == \
           wazuh_target_report['metadata']['n_agents'], "Some agents statuses have not been gathered correctly"
