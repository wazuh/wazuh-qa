import os

import pytest
from wazuh_testing.tools import configuration as config

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_cases_path = os.path.join(test_data_path, 'test_cases')
t1_file_path = os.path.join(test_cases_path, 'case_vd_performance.yaml')

t1_config, t1_metadata, t1_ids = config.get_test_cases_data(t1_file_path)


@pytest.mark.parametrize('metadata', t1_metadata, ids=t1_ids)
def test_vd_performance(configure_environment, metadata):
    """
    Steps:
        1. Run the necessary tasks to prepare the environment
        2. Run the event_injection playbook:
            2.1. Measure and run the tasks to test the module under load
            2.2. Generate CSV files
        3. Check the results
        4. Clean the environment
        5. Generate charts from CSV files
    """
