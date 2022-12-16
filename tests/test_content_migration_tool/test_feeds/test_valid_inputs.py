import glob
import os

import pytest
from wazuh_testing.cmt import CB_PROCESS_COMPLETED, LOG_FILE_PATH, OUTPUT_DIR
from wazuh_testing.cmt.utils import run_content_migration_tool, sanitize_configuration, validate_against_cve5_schema, \
                                    validate_against_delta_schema, query_publisher_db
from wazuh_testing.event_monitor import check_event
from wazuh_testing.tools import configuration
from wazuh_testing.tools.file import read_json_file, truncate_file


TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATION_PATH = os.path.join(TEST_DATA_PATH, 'configuration')
FEEDS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')

# Config and data paths
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_output_format.yaml')
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_generated_deltas.yaml')

# Get test cases data
t1_config, t1_metadata, t1_cases_id = configuration.get_test_cases_data(t1_cases_path)
t2_config, t2_metadata, t2_cases_id = configuration.get_test_cases_data(t2_cases_path)

# Sanitize the configuration to avoid creating a new function in the framework
t1_config = sanitize_configuration(t1_config)
t2_config = sanitize_configuration(t2_config)

# Feeds required
base_feed = os.path.join(FEEDS_PATH, 'arch', 'arch_well_formatted.json')
feed_with_vuln_added = os.path.join(FEEDS_PATH, 'arch', 'arch_new_cve.json')
feed_with_vuln_modified = os.path.join(FEEDS_PATH, 'arch', 'arch_updated_cve.json')


@pytest.mark.parametrize('configuration,metadata', zip(t1_config, t1_metadata), ids=t1_cases_id)
def test_output_format(configuration, metadata, build_cmt_config_file, clean_results):
    if 'debian' in metadata['output_file']:
        pytest.xfail('Expected to fail due to high memory consumption: wazuh/wazuh-content#334')
    elif 'alas' in metadata['output_file']:
        pytest.xfail('Expected to fail due to the complexity to mock the feed.')
    elif 'nvd' in metadata['output_file']:
        pytest.xfail('Expected to fail due to the the abscent of a valid test feed.')

    # Select the unique config file in the list
    config_file = build_cmt_config_file[0]
    json_output = '/'.join([OUTPUT_DIR, metadata['output_file']])

    output, err_output = run_content_migration_tool(f"-i {config_file}")
    if err_output is not None or output == '':
        pytest.fail(f"The execution of the binary have failed unexpectedly:\n{err_output}")

    # Wait until the procces finish
    check_event(callback=CB_PROCESS_COMPLETED, file_to_monitor=LOG_FILE_PATH)

    json_document = read_json_file(json_output)
    elements = json_document['elements']

    errors = validate_against_cve5_schema(elements)
    # Make errors human-readable
    errors = '\n'.join(errors)

    # The output must not have format errors
    assert len(errors) == 0, 'The output feed is invalid according to the CVE5 schema.\n' \
                             f"Validation Error: {errors}Tool result at: {json_output}.\nTool output:\n{output}"


@pytest.mark.parametrize('configuration,metadata', zip(t2_config, t2_metadata), ids=t2_cases_id)
def test_generated_deltas(configuration, metadata, build_cmt_config_file, clean_results):
    if metadata['operation'] is None:
        pytest.xfail('Expected to fail due to an defect in the tool.')
    delta_filepath = '/'.join([OUTPUT_DIR, metadata['output_folder']])
    operation = metadata['operation']
    expected_cves = metadata['expected_cves']
    config_files = build_cmt_config_file

    # Run the tool for each configuration file in the test case (to get the desired state)
    for config in config_files:
        truncate_file(LOG_FILE_PATH)
        output, err_output = run_content_migration_tool(f"-i {config}")
        if err_output is not None or output == '':
            pytest.fail(f"The execution of the binary have failed unexpectedly:\n{err_output}")
        # Wait until the procces finish
        check_event(callback=CB_PROCESS_COMPLETED, file_to_monitor=LOG_FILE_PATH)

    all_files = glob.glob(os.path.join(delta_filepath, '*'))
    # Select the newest delta file generated (where the results are) from the list of all files
    newest_file = max(all_files, key=os.path.getctime)

    # If the delta file is not a valid JSON, then store its content in raw format (case: NO_CHANGES_IN_FEED)
    try:
        delta_file_content = read_json_file(newest_file)
        elements = delta_file_content['elements']
    except TypeError:
        with open(newest_file, 'r') as f:
            delta_file_content = f.read()

    if operation in ('insert', 'update'):
        query = f"SELECT * FROM table_name_{metadata['table_name']} ORDER BY cve_id ASC LIMIT {len(expected_cves)};"
        # Note: `ORDER BY cve_id` this relies on the CVEs inserted in the DB, so make sure that the CVEs are correctly
        # sorted in each file of the input feeds
        # Reason: There is no column to identify which elements were last inserted into the database.
        errors = validate_against_delta_schema(elements)
        # Make errors human-readable
        errors = '\n'.join(errors)
        assert len(errors) == 0, 'The delta file is invalid according to the CVE5 schema.\n' \
                                 f"Validation Error: {errors}Tool result at: {newest_file}.\nTool output:\n{output}"
        # Check if there is any difference between the data stored in the DB and the file with the deltas
        integrity_errors = []
        query_result = query_publisher_db(query)
        for cve_idx, cve in enumerate(elements):
            required_fields = ['cve_id', 'data_hash', 'data_blob']
            # idx points to the current CVE
            # e.g.: `query_result[cve_idx][field_index]` is retrieving the `data_blob` field of the current CVE.
            for field_index, field in enumerate(required_fields):
                if cve[field] != query_result[cve_idx][field_index]:
                    integrity_errors.append({'cve': cve['cve_id'], 'bad_field': field})

        assert len(integrity_errors) == 0, 'The CVE stored in the DB is not the same as in the delta file.\n' \
                                           f"Inconsistencies:\n{integrity_errors}"
    elif operation == 'delete':
        query = f"SELECT * FROM table_name_{metadata['table_name']};"
        query_result = query_publisher_db(query)
        assert len(query_result) == len(expected_cves), 'The number of CVEs stored is not the expected.\n' \
                                                        f"Expected: {expected_cves}\nResult: {query_result}"
        # Idx = 0: Select `cve_id` field
        stored_cve_ids = [cve[0] for cve in query_result]
        for cve in elements:
            if cve['cve_id'] in expected_cves:
                continue
            assert cve['cve_id'] not in stored_cve_ids, 'Some CVEs continue stored in the DB.\n' \
                                                        f"Expected CVEs: {expected_cves}\nResult: {stored_cve_ids}"
    else:
        assert delta_file_content == 'null', 'A delta was generated, but it should not have been generated.\n' \
                                             f"Current content: {delta_file_content}"
