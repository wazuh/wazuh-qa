import os
import pytest
from tempfile import gettempdir

import wazuh_testing as fw
from wazuh_testing.tools import configuration as config
from wazuh_testing import event_monitor as evm


# Amount of repeated log to be found in ossec.log
REPEATED_LOGS = 2
# Test cases data
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_recurrent_attacks_after_timeout_expired.yaml')
ossec_log = os.path.join(gettempdir(), 'test_recurrent_attacks_after_timeout_expired', 'ossec.log')

# Playbooks
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['get_logs.yaml']
teardown_playbooks = ['teardown.yaml']

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)

# Configuration variables
timeout = configuration_metadata[0]['timeout_vars']
repeated_offenders_timeout = ",".join(configuration_metadata[0]['repeated_offenders_timeout'])
configuration_extra_vars = {}
configuration_extra_vars.update({'timeout_vars': timeout, 'repeated_offenders_timeout': repeated_offenders_timeout})


@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
@pytest.mark.xfail(reason='Expected error. Issue https://github.com/wazuh/wazuh/issues/XXXX')
def test_recurrent_attacks_after_timeout_expired(configure_environment, metadata, get_information):
    '''
    description: Check that active-response repeated_offenders blocks the attacks for the respective timeout if the
                 attack proceeds before the active-response timeout have expired.

    test_phases:
        - Set a custom Wazuh configuration.
        - Generates RDP attacks
        - Check in the agent ossec.log file that the attacks have been blocked according to the timeout.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - configurate_environment:
            type: fixture
            brief: Set the wazuh configuration according to the configuration playbook.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - get_information:
            type: fixture
            brief: Generate RDP attack to the agent and copy the ossec.log file to a specific local folder to
                   be analyzed.

    assertions:
        - Verify that the logs have been generated.

    input_description:
        - The `configuration.yaml` file provides the module configuration for this test.
        - The `get_logs.yaml` file provides the function to copy the log file to a temporary folder and provides the
          playbook to generate the RDP attack.
    '''
    for expected_log in metadata['extra_vars']['repeated_offenders_logs']:
        accum_results = 1
        if '5s' in expected_log:
            accum_results = REPEATED_LOGS
        evm.check_event(callback=expected_log, file_to_monitor=ossec_log,
                        timeout=fw.T_5, accum_results=accum_results,
                        error_message=f"Could not find the event '{expected_log}' in ossec.log file")
