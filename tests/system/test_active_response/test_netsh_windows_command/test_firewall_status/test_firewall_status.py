import os
import pytest
from tempfile import gettempdir

import wazuh_testing as fw
from wazuh_testing.tools import configuration as config
from wazuh_testing import event_monitor as evm


# Test cases data
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_firewall_status.yaml')
active_responses_log = os.path.join(gettempdir(), 'test_firewall_status', 'active-responses.log')

# Playbooks
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['generate_events.yaml']
teardown_playbooks = ['teardown.yaml']

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)


def check_event(expected_log):
    """Check for the espected log.

    Args:
        expected_log (str): Text to find in the alerts.json file
    """
    evm.check_event(callback=expected_log, file_to_monitor=active_responses_log,
                    timeout=fw.T_5,
                    error_message=f"Could not find the event '{expected_log}' in active-responses.log file")


@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_firewall_status(metadata, configure_environment, generate_events):
    '''
    description: Check that active-response detect that the firewall is disabled/enabled when and hydra attack is
                 performed.

    test_phases:
        - Set a custom Wazuh configuration.
        - Generates RDP attacks
        - Check in the agent active-responses.log file that the firewall is disabled/enabled.

    wazuh_min_version: 4.5.0

    tier: 0

    parameters:
        - configurate_environment:
            type: fixture
            brief: Set the wazuh configuration according to the configuration playbook.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - generate_events:
            type: fixture
            brief: Generate RDP attack to the agent and copy the ossec.log and active-responses.log file to a specific
                   local folder to be analyzed.

    assertions:
        - Verify that the logs have been generated.

    input_description:
        - The `configuration.yaml` file provides the module configuration for this test.
        - The `generate_events.yaml` file provides the function to copy the log file to a temporary folder and
          provides the playbook to generate the RDP attack.
    '''
    status = metadata['extra_vars']['firewall_status']
    for expected_log in metadata['extra_vars']['firewall_status_logs']:
        if 'disabled' in status:
            check_event(expected_log)
        else:
            with pytest.raises(TimeoutError):
                check_event(expected_log)
                raise AttributeError(f'Unexpected log {expected_log}')
