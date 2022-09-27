import os
import pytest
from tempfile import gettempdir

from wazuh_testing.tools import configuration as config


# Test cases data
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_file_path = os.path.join(test_data_path, 'test_cases', 'cases_repeated_offenders_negative_values.yaml')
ossec_log = os.path.join(gettempdir(), 'test_repeated_offenders_negative_values', 'ossec.log')

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
def test_repeated_offenders_negative_values(configure_environment, metadata, get_information):
    '''
    description: Check that active-response repeated_offenders timeout does not accept negative values.

    test_phases:
        - Set a custom Wazuh configuration.
        - Check in the agent ossec.log file for error or warning messages.

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
    pass
