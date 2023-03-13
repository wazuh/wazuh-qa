import os
from datetime import datetime

import pytest
from wazuh_testing import T_20, global_parameters
from wazuh_testing.modules.aws import event_monitor
from wazuh_testing.modules.aws import constants as cons
from wazuh_testing.modules.aws.cli_utils import call_aws_module
from wazuh_testing.modules.aws.db_utils import (
    get_multiple_s3_db_row,
    get_s3_db_row,
    s3_db_exists,
    services_db_exists,
    get_service_db_row, table_exists
)
from wazuh_testing.modules.aws.s3_utils import get_last_file_key, upload_file
from wazuh_testing.tools.configuration import (
    get_test_cases_data,
    load_configuration_template,
)

pytestmark = [pytest.mark.server]


# Generic vars
TEMPLATE_DIR = 'configuration_template'
TEST_CASES_DIR = 'test_cases'
MODULE = 'only_logs_after_test_module'
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, TEMPLATE_DIR, MODULE)
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, TEST_CASES_DIR, MODULE)
local_internal_options = {'wazuh_modules.debug': '2', 'monitord.rotate_log': '0'}

# --------------------------------------------- TEST_BUCKET_WITHOUT_ONLY_LOGS_AFTER ------------------------------------
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_without_only_logs_after.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_without_only_logs_after.yaml')

t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(
    t1_configurations_path, t1_configuration_parameters, t1_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_bucket_without_only_logs_after(
    configuration, metadata, upload_and_delete_file_to_s3, load_wazuh_basic_configuration, set_wazuh_configuration,
    clean_s3_cloudtrail_db, configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function,
    wazuh_log_monitor
):
    """
    description: Only the log uploaded during execution is processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
    wazuh_min_version: 4.5.0
    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - upload_and_delete_file_to_s3:
            type: fixture
            brief: Upload a file for the day of the execution and delete after the test.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - clean_s3_cloudtrail_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - wazuh_log_monitor:
            type: fixture
            brief: Return a `ossec.log` monitor.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    bucket_name = metadata['bucket_name']
    bucket_type = metadata['bucket_type']
    expected_results = metadata['expected_results']
    table_name = metadata.get('table_name', bucket_type)

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--aws_profile', 'qa',
        '--type', bucket_type,
        '--debug', '2'
    ]

    # Check AWS module started
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start,
        error_message='The AWS module did not start as expected',
    ).result()

    # Check command was called correctly
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters),
        error_message='The AWS module was not called with the correct parameters',
    ).result()

    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_event_processed,
        error_message='The AWS module did not process the expected number of events',
        accum_results=expected_results
    ).result()

    assert s3_db_exists()

    data = get_s3_db_row(table_name=table_name)

    assert bucket_name in data.bucket_path
    assert metadata['uploaded_file'] == data.log_key


# --------------------------------------------- TEST_BUCKET_WITH_ONLY_LOGS_AFTER ---------------------------------------
t2_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_with_only_logs_after.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_with_only_logs_after.yaml')

t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(
    t2_configurations_path, t2_configuration_parameters, t2_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_bucket_with_only_logs_after(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration, clean_s3_cloudtrail_db,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, wazuh_log_monitor
):
    """
    description: All logs with a timestamp greater than the only_logs_after value are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
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
        - clean_s3_cloudtrail_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - wazuh_log_monitor:
            type: fixture
            brief: Return a `ossec.log` monitor.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    bucket_name = metadata['bucket_name']
    bucket_type = metadata['bucket_type']
    only_logs_after = metadata['only_logs_after']
    expected_results = metadata['expected_results']
    table_name = metadata.get('table_name', bucket_type)

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--aws_profile', 'qa',
        '--only_logs_after', only_logs_after,
        '--type', bucket_type,
        '--debug', '2'
    ]
    # Check AWS module started
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start,
        error_message='The AWS module did not start as expected',
    ).result()

    # Check command was called correctly
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters),
        error_message='The AWS module was not called with the correct parameters',
    ).result()

    wazuh_log_monitor.start(
        timeout=T_20,
        callback=event_monitor.callback_detect_event_processed,
        accum_results=expected_results,
        error_message='The AWS module did not process the expected number of events',
    ).result()

    assert s3_db_exists()

    for row in get_multiple_s3_db_row(table_name=table_name):
        assert bucket_name in row.bucket_path
        assert (
            datetime.strptime(only_logs_after, '%Y-%b-%d') < datetime.strptime(str(row.created_date), '%Y%m%d')
        )


# -------------------------------------------- TEST_SERVICE_WITH_ONLY_LOGS_AFTER ---------------------------------------
t3_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'service_configuration_with_only_logs_after.yaml')
t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_service_with_only_logs_after.yaml')

t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
t3_configurations = load_configuration_template(
    t3_configurations_path, t3_configuration_parameters, t3_configuration_metadata
)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
def test_service_with_only_logs_after(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration, clean_aws_services_db,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, wazuh_log_monitor
):
    """
    description: All logs with a timestamp greater than the only_logs_after value are processed.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were sent to analysisd. Only the logs whose timestamp is greater than
              the date specified in the configuration should be processed.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file.
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
        - clean_aws_services_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - wazuh_log_monitor:
            type: fixture
            brief: Return a `ossec.log` monitor.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check in the bucket that the uploaded log was removed.
    input_description:
        - The `configuration_defaults` file provides the module configuration for this test.
        - The `cases_defaults` file provides the test cases.
    """
    service_type = metadata['service_type']
    only_logs_after = metadata['only_logs_after']
    expected_results = metadata['expected_results']

    parameters = [
        'wodles/aws/aws-s3',
        '--service', service_type,
        '--aws_profile', 'qa',
        '--only_logs_after', only_logs_after,
        '--regions', 'us-east-1',
        '--debug', '2'
    ]

    # Check AWS module started
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start,
        error_message='The AWS module did not start as expected',
    ).result()

    # Check command was called correctly
    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters),
        error_message='The AWS module was not called with the correct parameters',
    ).result()

    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=event_monitor.callback_detect_inspector_event_processed(expected_results),
        error_message='The AWS module did not process the expected number of events',
    ).result()

    assert services_db_exists()

    data = get_service_db_row(table_name="aws_services")

    assert data.service == service_type
    assert datetime.strptime(data.timestamp, '%Y-%m-%d %H:%M:%S.%f') == datetime.strptime(only_logs_after, '%Y-%b-%d')


# ---------------------------------------------------- TEST_MULTIPLE_CALLS ---------------------------------------------
t4_cases_path = os.path.join(TEST_CASES_PATH, 'cases_multiple_calls.yaml')

_, t4_configuration_metadata, t4_case_ids = get_test_cases_data(t4_cases_path)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('metadata', t4_configuration_metadata, ids=t4_case_ids)
def test_bucket_multiple_calls(
    metadata, clean_s3_cloudtrail_db, load_wazuh_basic_configuration, restart_wazuh_function, delete_file_from_s3
):
    """
    description: Call the AWS module multiple times with different only_logs_after values.
    test_phases:
        - setup:
            - Delete the `s3_cloudtrail.db`.

        - test:
            - Call the module without only_logs_after and check that no logs were processed.
            - Upload a log file for the day of the test execution and call the module with the same parameters as
              before, check that the uploaded logs were processed.
            - Call the module with the same parameters and check that no logs were processed, there were no duplicates.
            - Call the module with only_logs_after set in the past and check that the expected number of logs were
              processed.
            - Call the module with the same parameters in and check there were no duplicates.
            - Call the module with only_logs_after set with an older date check that old logs were processed without
              duplicates.
            - Call the module with only_logs_after set with an early date than setted previously and check that no logs
              were processed, there were no duplicates.

        - teardown:
            - Delete the `s3_cloudtrail.db`.
            - Delete the uploaded files.
    wazuh_min_version: 4.5.0
    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - clean_s3_cloudtrail_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - restart_wazuh_daemon:
            type: fixture
            brief: Restart the wazuh service.
        - delete_file_from_s3:
            type: fixture
            brief: Delete the a file after the test execution.
    input_description:
        - The `cases_multiple_calls` file provides the test cases.
    """
    ONLY_LOGS_AFTER_PARAM = '--only_logs_after'

    bucket_type = metadata['bucket_type']
    bucket_name = metadata['bucket_name']

    base_parameters = [
        '--bucket', bucket_name,
        '--type', bucket_type,
        '--regions', 'us-east-1',
        '--aws_profile', 'qa',
        '--debug', '2'
    ]

    # Call the module without only_logs_after and check that no logs were processed
    last_marker_key = datetime.utcnow().strftime(cons.PATH_DATE_FORMAT)
    if bucket_type == cons.CUSTOM_TYPE or (bucket_type == cons.GUARD_DUTY_TYPE and 'native' not in bucket_name):
        event_monitor.check_marker_from_output(
            command_output=call_aws_module(*base_parameters),
            file_key=last_marker_key
        )
    else:
        event_monitor.check_non_processed_logs_from_output(
            command_output=call_aws_module(*base_parameters),
            bucket_type=bucket_type
        )

    # Call the module with only_logs_after set in the past and check that the expected number of logs were
    # processed
    event_monitor.check_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2022-NOV-20'),
        expected_results=3
    )

    # Call the module with the same parameters in and check there were no duplicates
    event_monitor.check_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2022-NOV-20'),
        bucket_type=bucket_type,
        expected_results=metadata.get('expected_skipped_logs_step_3', 1)
    )

    # Call the module with only_logs_after set with an early date than setted previously and check that no logs
    # were processed, there were no duplicates
    expected_skipped_logs_step_4 = metadata.get('expected_skipped_logs_step_4', 1)
    event_monitor.check_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2022-NOV-22'),
        bucket_type=bucket_type,
        expected_results=expected_skipped_logs_step_4 - 1 if expected_skipped_logs_step_4 > 1 else 1
    )

    # Upload a log file for the day of the test execution and call the module without only_logs_after and check that
    # only the uploaded logs were processed and the last marker is specified in the DB.
    if bucket_type != cons.CUSTOM_TYPE:
        last_marker_key = get_last_file_key(bucket_type, bucket_name)
    metadata['filename'] = upload_file(bucket_type, bucket_name)

    event_monitor.check_marker_from_output(
        command_output=call_aws_module(*base_parameters),
        file_key=last_marker_key
    )


# -------------------------------------------- TEST_SERVICE_MULTIPLE_CALLS ---------------------------------------------
t5_cases_path = os.path.join(TEST_CASES_PATH, 'cases_service_multiple_calls.yaml')

_, t5_configuration_metadata, t5_case_ids = get_test_cases_data(t5_cases_path)


@pytest.mark.tier(level=1)
@pytest.mark.parametrize('metadata', t5_configuration_metadata, ids=t5_case_ids)
def test_service_multiple_calls(
    metadata, clean_aws_services_db, load_wazuh_basic_configuration, restart_wazuh_function
):
    """
    description: Call the AWS module multiple times with different only_logs_after values.
    test_phases:
        - setup:
            - Delete the `aws_services.db`.
        - test:
            - Call the module without only_logs_after and check that no logs were processed.
            - Call the module with only_logs_after set in the past and check that the expected number of logs were
              processed.
            - Call the module with the same parameters in and check there were no duplicates.
            - Call the module with only_logs_after set with an early date than setted previously and check that no logs
              were processed, there were no duplicates.
        - teardown:
            - Delete the `aws_services.db`.
    wazuh_min_version: 4.5.0
    parameters:
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - clean_aws_services_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - restart_wazuh_daemon:
            type: fixture
            brief: Restart the wazuh service.
    input_description:
        - The `cases_multiple_calls` file provides the test cases.
    """
    ONLY_LOGS_AFTER_PARAM = '--only_logs_after'

    service_type = metadata['service_type']

    base_parameters = [
        '--service', service_type,
        '--regions', 'us-east-1',
        '--aws_profile', 'qa',
        '--debug', '2'
    ]

    # Call the module without only_logs_after and check that no logs were processed
    event_monitor.check_inspector_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters), expected_results=1
    )

    # Call the module with only_logs_after set in the past and check that the expected number of logs were
    # processed
    event_monitor.check_inspector_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-30'),
        events_sent=4
    )

    # Call the module with the same parameters in and check there were no duplicates
    event_monitor.check_inspector_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-30'), expected_results=1
    )

    # Call the module with only_logs_after set with an early date than setted previously and check that no logs
    # were processed, there were no duplicates
    event_monitor.check_inspector_non_processed_logs_from_output(
        command_output=call_aws_module(*base_parameters, ONLY_LOGS_AFTER_PARAM, '2023-JAN-31'), expected_results=1
    )
