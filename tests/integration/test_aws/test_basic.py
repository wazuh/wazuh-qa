import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.modules.aws import callbacks
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import (
    get_test_cases_data,
    load_configuration_template,
)
from wazuh_testing.tools.monitoring import FileMonitor

pytestmark = [pytest.mark.server]


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'basic_test_module')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'basic_test_module')
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0'}
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# ---------------------------------------------------- TEST_DEFAULTS ---------------------------------------------------
# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_defaults.yml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_defaults.yml')

# Enabled test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_defaults(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function
):
    """
    description: The module is invoked with the expected parameters and no error occurs.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check in the ossec.log that no errors occurs.
        - tierdown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
    wazuh_min_version: 4.5.0
    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check in the log that no errors occurs.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    parameters = [
        "wodles/aws/aws-s3",
        "--bucket", metadata["bucket_name"],
        "--aws_profile", "qa",
        "--type", metadata["bucket_type"],
        "--debug", "2"
    ]

    # Check AWS module started
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=callbacks.callback_detect_aws_module_start,
        error_message="The AWS module didn't start, maybe it crash",
    ).result()

    # Check command was called correctly
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=callbacks.callback_detect_aws_module_called(parameters),
        error_message="The AWS module wasn't called with the correct parameters",
    ).result()

    # Detect any ERROR message
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(
            timeout=global_parameters.default_timeout,
            callback=callbacks.callback_detect_aws_wmodule_err,
            error_message="Some errors were found related to AWS module",
        ).result()