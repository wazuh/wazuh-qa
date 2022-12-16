import os

import pytest
from wazuh_testing.cmt.utils import sanitize_configuration, run_content_migration_tool
from wazuh_testing.tools import configuration


TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATION_PATH = os.path.join(TEST_DATA_PATH, 'configuration')

# Config and data paths
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_inputs.yaml')

# Get test cases data
t1_config, t1_metadata, t1_case_ids = configuration.get_test_cases_data(t1_cases_path)

# Sanitize the configuration to avoid creating a new function in the framework
t1_config = sanitize_configuration(t1_config)


@pytest.mark.parametrize('configuration, metadata', zip(t1_config, t1_metadata), ids=t1_case_ids)
def test_invalid_inputs(configuration, metadata, build_cmt_config_file):
    expected_error = metadata['error']
    config_file = build_cmt_config_file[0]

    output, err_output = run_content_migration_tool(f"-i {config_file}")
    if output is not None:
        pytest.fail(f"The binary execution is expected to fail but it does not:\n {output}")

    assert expected_error in err_output, 'The expected error was not found in the output.\n' \
                                         f"Expected:\n{expected_error}\n" \
                                         f"Got:\n{err_output}"
