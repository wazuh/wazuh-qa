import pytest
from wazuh_testing import global_parameters


def test_keep_alives(get_report):
    """Check that:
        - Agents are connected everytime 
        - N tcp connections is equal to n of active agents
    """
    ## Check max difference in agent
    ## Check max difference in managers

    report = global_parameters.report

    ## Agent
    assert report['agents']['wazuh-agentd']['max_diff_ack_keep_alive'] < 37

    # Manager
    report = global_parameters.report
    keep_alives = report['managers']['wazuh-remoted']['keep_alives']
    
    max_differences = [keep_alives[agent]['max_difference'] for agent in keep_alives.keys()]
    assert max(max_differences) < 30
