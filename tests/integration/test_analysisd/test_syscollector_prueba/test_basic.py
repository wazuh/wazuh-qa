import os
import pytest

from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.analysisd import event_monitor as evm
from wazuh_testing.processes import check_if_daemons_are_running
from wazuh_testing.tools import (ANALYSISD_QUEUE_SOCKET_PATH, ALERT_FILE_PATH)
from wazuh_testing.analysis import CallbackWithContext, callback_check_syscollector_alert

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
TEST_RULES_PATH = os.path.join(TEST_DATA_PATH, 'rules')
local_internal_options = {'analysisd.debug': '2'}

# Variables
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]
receiver_sockets = None
alert_timeout = 5
file_to_monitor = ALERT_FILE_PATH

# ---------------------------------------------------- TEST_EVENTS ----------------------------------------------------
# Configuration and cases data
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_syscollector_integration.yaml')
rule_file = "syscollector_rules.xml"

# Enabled test configurations (t1)
_, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)


@pytest.mark.tier(level=2)
@pytest.mark.parametrize('metadata', t1_configuration_metadata, ids=t1_case_ids)
def test_syscollector(metadata, configure_local_internal_options_module, mock_agent_module,
                 configure_custom_rules, restart_analysisd, wait_for_analysisd_startup,
                 connect_to_sockets_function, file_monitoring):
    """
    test description
    """

    # Get mock agent_id to create syscollector header
    agent_id = mock_agent_module
    event_header = f"d:[{agent_id}] {metadata['event_header']}"

    #for stage in test_case['test_case']:

    # Add agent_id alert check
    alert_expected_values = metadata['alert_expected_values']
    alert_expected_values['agent.id'] = agent_id

    # Create full message by header and payload concatenation
    test_msg = event_header + metadata['event_payload']

    # Send delta to analysisd queue
    receiver_sockets[0].send(test_msg)

    # Set callback according to stage parameters
    alert_callback = CallbackWithContext(callback_check_syscollector_alert, alert_expected_values)

    # Find expected outputs
    log_monitor.start(timeout=alert_timeout,
                       callback=alert_callback,
                       error_message=f"Timeout expecting {metadata['description']} message.")
