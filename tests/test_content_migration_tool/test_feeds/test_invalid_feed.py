import os
import pytest
from wazuh_testing.tools import configuration
from content_migration_tool import ContentMigrationTool


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configuration_path = os.path.join(test_data_path, 'configuration')

# Config and data paths
test_cases_path = os.path.join(test_data_path, 'test_cases')
t1_config_path = os.path.join(configuration_path, 'config_file.yaml')
t1_cases_path = os.path.join(test_cases_path, 'cases_invalid_feed.yaml')

# Get test cases data
t1_config, t1_metadata, t1_case_ids = configuration.get_test_cases_data(t1_cases_path)

# Sanitize the configuration to avoid creating a new function in the framework
for tc_config in t1_config:
    for key in tc_config:
        tc_config[key.lower()] = tc_config.pop(key)


@pytest.mark.parametrize('configuration, metadata', zip(t1_config, t1_metadata), ids=t1_case_ids)
def test_invalid_feed(configuration, metadata, build_cmt_config_file):
    expected_error = metadata['error']
    config_file = build_cmt_config_file
    cmt = ContentMigrationTool(f"-i {config_file}")

    tool_output = cmt.run()

    print(tool_output)

    assert expected_error in tool_output, 'The expected error was not found in the output.\n' \
                                          f"Expected:\n{expected_error}\n" \
                                          f"Got:\n{tool_output}"
