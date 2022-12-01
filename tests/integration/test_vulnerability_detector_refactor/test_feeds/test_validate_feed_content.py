import os
import pytest
from wazuh_testing.tools import file
from wazuh_testing.tools import configuration

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_cases_path = os.path.join(test_data_path, 'test_cases')
feed_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data')


# Configuration and cases data
test_feeds_path = os.path.join(test_cases_path, 'cases_validate_feed_content.yaml')

test_input_nvd_feed_path = os.path.join(feed_path, 'input_feed', 'nvd', 'nvd_feed.json')
test_input_nvd_feed_less_than_path = os.path.join(feed_path, 'input_feed', 'nvd', 'nvd_less_than.json')


test_output_feed_path = os.path.join(feed_path, 'output_feed', 'cve5.json')
test_output_rejected_feed_path = os.path.join(feed_path, 'output_feed', 'cve5_rejected_feed.json')

_, configuration_metadata, test_case_ids = configuration.get_test_cases_data(test_feeds_path)

# Set offline custom feeds configuration
to_modify = ['CUSTOM_NVD_FEED_JSON_PATH', 'CUSTOM_NVD_FEED_JSON_LESS_THAN_PATH']
new_values = [test_input_nvd_feed_path, test_input_nvd_feed_less_than_path]

configuration_metadata = configuration.update_configuration_template(configuration_metadata, to_modify, new_values)

output_path = "/home/belen/Feed-output/build/"
parser_type_json = "JSON"


@pytest.mark.parametrize('metadata', configuration_metadata, ids=test_case_ids)
def test_feed_content(metadata):

    print(test_output_feed_path)
    # Validate input file is a correct json
    assert file.validate_json_file(test_input_nvd_feed_path), "File is not JSON 'parseable'"
    assert file.validate_json_file(test_input_nvd_feed_less_than_path), "File is not JSON 'parseable'"

    # Execute migration tool
    os.chdir("/home/belen/Repositories/wazuh-content/build/third_party_migration/")
    migration_tool = os.system(f"./content_migration -i {metadata['feed_path']} -t {metadata['format']} -o {output_path}")

    # Validate output file is a correct json
    assert file.validate_json_file(test_output_feed_path), "File is not JSON 'parseable'"


    # Validate required content
    nvd_file = file.read_json_file(test_input_nvd_feed_path)
    cve5_file= file.read_json_file(test_output_feed_path)
    cve5_file_rejected = file.read_json_file(test_output_rejected_feed_path)

    assert cve5_file['data'][0]['data_blob']['data'][0]['dataType'] == 'CVE_RECORD'
    assert cve5_file['data'][0]['data_blob']['data'][0]['dataVersion'] == '5.0'

    if cve5_file['data'][0]['data_blob']['data'][0]['cveMetadata']['state'] == 'PUBLISHED':
        assert nvd_file['CVE_Items'][0]['cve']['CVE_data_meta']['ID'] == cve5_file['data'][0]['data_blob']['data'][0]['cveMetadata']['cveId']
        #assert nvd_file['CVE_Items'][0]['cve']['CVE_data_meta']['ASSIGNER'] == cve5_file['data'][0]['data_blob']['data'][0]['cveMetadata']['assignerOrgId'] to be define by core
        #assert nvd_file['CVE_Items'][0]['cve']['CVE_data_meta']['ASSIGNER'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['providerMetadata']['orgId'] to be define by core
        assert nvd_file['CVE_Items'][0]['cve']['description']['description_data'][0]['lang'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['descriptions'][0]['lang']
        assert nvd_file['CVE_Items'][0]['cve']['description']['description_data'][0]['value'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['descriptions'][0]['value']
        #assert nvd_file['CVE_Items'][0]['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['affected'][0]['cpes'][0] validar si es solo para NVD
        assert nvd_file['CVE_Items'][0]['cve']['references']['reference_data'][0]['url'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['references'][0]['url']
        assert nvd_file['CVE_Items'][0]['cve']['problemtype']['problemtype_data'][0]['description'][0]['lang'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['problemTypes'][0]['descriptions'][0]['lang']
        assert nvd_file['CVE_Items'][0]['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['problemTypes'][0]['descriptions'][0]['description']

        ## Todo: Affected section is complex, different for each vendor.Validate vendor and product (check where is obtained in each vendor)
        version_less_equal = ["data", 0, "data_blob", "data", 0, "containers", "cna", "affected", 0, "versions", 0, "lessThanOrEqual"]
        version_less_than = ["data", 0, "data_blob", "data", 0, "containers", "cna", "affected", 0, "versions", 0, "lessThan"]
        if  keys_exists(cve5_file, version_less_equal):
            assert nvd_file['CVE_Items'][0]['configurations']['nodes'][0]['cpe_match'][0]['versionEndIncluding'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['affected'][0]['versions'][0]['lessThanOrEqual']
        elif keys_exists(cve5_file, version_less_than):
            assert nvd_file['CVE_Items'][0]['configurations']['nodes'][0]['cpe_match'][0]['versionEndExcluding'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['affected'][0]['versions'][0]['lessThan']

    elif cve5_file['data'][0]['data_blob']['data'][0]['cveMetadata']['state'] == 'REJECTED':
        assert nvd_file['CVE_Items'][0]['cve']['CVE_data_meta']['ID'] == cve5_file_rejected['data'][0]['data_blob']['data'][0]['cveMetadata']['cveId']
        #assert nvd_file['CVE_Items'][0]['cve']['CVE_data_meta']['ASSIGNER'] == cve5_file['data'][0]['data_blob']['data'][0]['cveMetadata']['assignerOrgId'] to be define by core
        #assert nvd_file['CVE_Items'][0]['cve']['CVE_data_meta']['ASSIGNER'] == cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['providerMetadata']['orgId'] to be define by core
        #assert nvd_file['CVE_Items'][0]['cve']['lang'] == cve5_file_rejected['data'][0]['data_blob']['data'][0]['containers']['cna']['rejectedReasons'][0]['lang'] Research a sample rejected input feed
        #assert nvd_file['CVE_Items'][0]['cve']['value'] == cve5_file_rejected['data'][0]['data_blob']['data'][0]['containers']['cna']['rejectedReasons'][0]['value']
        assert cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['rejectedReasons'][0]['lang']
        assert cve5_file['data'][0]['data_blob']['data'][0]['containers']['cna']['rejectedReasons'][0]['value']



def keys_exists(element, keys):
    '''
    Check if *keys (nested) exists in `element` (dict).
    '''
    if not isinstance(element, dict):
        raise AttributeError('`element` argument must be of type: dict')
    if not isinstance(keys, list):
        raise AttributeError('`keys` argument must be of type: dict')
    if keys == []:
        raise AttributeError('`keys` list is empty. At least 1 element must exist in the list.')

    for key in keys:
        try:
            element = element[key]
        except KeyError:
            return False
    return True
