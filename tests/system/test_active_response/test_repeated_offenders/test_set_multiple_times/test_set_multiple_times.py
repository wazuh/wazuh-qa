import os
import pytest
from tempfile import gettempdir

import wazuh_testing as fw
from wazuh_testing.tools import configuration as config
from wazuh_testing import event_monitor as evm


# Test cases data
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_set_multiple_times.yaml')
ossec_log = os.path.join(gettempdir(), 'test_set_multiple_times', 'ossec.log')

# Playbooks
configuration_playbooks = ['configuration.yaml']
events_playbooks = ['get_logs.yaml']
teardown_playbooks = ['teardown.yaml']

# Configuration
configurations, configuration_metadata, cases_ids = config.get_test_cases_data(test_cases_file_path)

# Configuration variables
timeout = configuration_metadata[0]['timeout_vars']
repeated_offenders_timeout_1 = ",".join(configuration_metadata[0]['repeated_offenders_timeout_1'])
repeated_offenders_timeout_2 = ",".join(configuration_metadata[0]['repeated_offenders_timeout_2'])
configuration_extra_vars = {}
configuration_extra_vars.update({'timeout_vars': timeout, 'repeated_offenders_timeout_1': repeated_offenders_timeout_1,
                                 'repeated_offenders_timeout_2': repeated_offenders_timeout_2})


@pytest.mark.parametrize('metadata', configuration_metadata, ids=cases_ids)
def test_set_multiple_times(configure_environment, metadata, get_information):
    '''
    description: Check that the active-response repeated_offenders configuration take the first repeated_offenders tag
                 when there is a repeated tag.

    test_phases:
        - Set a custom Wazuh configuration.
        - Check in the agent ossec.log file that the repeated_offenders takes the first tag.

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
            brief: Copy the ossec.log file to a specific local folder to be analyzed.

    assertions:
        - Verify that the logs have been generated.

    input_description:
        - The `configuration.yaml` file provides the module configuration for this test.
        - The `get_logs.yaml` file provides the function to copy the log file to a temporary folder.
    '''
    for expected_log in metadata['extra_vars']['repeated_offenders_logs_1']:
        evm.check_event(callback=expected_log, file_to_monitor=ossec_log,
                        timeout=fw.T_5,
                        error_message=f"Could not find the event '{expected_log}' in ossec.log file")

    for expected_log in metadata['extra_vars']['repeated_offenders_logs_2']:
        with pytest.raises(Exception):
            evm.check_event(callback=expected_log,
                            file_to_monitor=ossec_log,
                            timeout=fw.T_5,
                            error_message=f"Could not find the event '{expected_log}' in ossec.log file")
