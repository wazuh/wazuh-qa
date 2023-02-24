import yaml
import argparse
import sys
import os
from collections import OrderedDict


policy_values_expected_order = ['id', 'title', 'description', 'rationale', 'impact', 'remediation', 'references', 'compliance', 'condition', 'rules']

policy_compliance_order = ['cis', 'cis_csc_v8', 'cis_csc_v7', 'nist_sp_800-53' 'iso_27001-2013', 'cmmc_v2.0', 'hipaa',
                           'pci_dss_3.2.1', 'pci_dss_4.0', 'soc_2', 'mitre_techniques', 'mitre_tactics',
                           'mitre_mitigations']


automatic_compliace_mapping_policies = {
    'cis_rhel9_linux': ['cmmc_v2.0', 'pci_dss_3.2.1', 'soc_2', 'pci_dss_4.0', 'hipa', 'iso_27001-2013'],
    'cis_macOS_13': ['mitre_techniques', 'cmmc_v2.0','pci_dss_3.2.1', 'soc_2', 'pci_dss_4.0', 'hipa', 'iso_27001-2013', 'mitre_tactics', 'mitre_mitigations', 'nist_sp_800-53'],
    'cis_debian11':  ['cmmc_v2.0','pci_dss_3.2.1', 'soc_2', 'pci_dss_4.0', 'hipa', 'iso_27001-2013', 'nist_sp_800-53'],
    'cis_amazon_linux_2022':  ['cmmc_v2.0','pci_dss_3.2.1', 'soc_2', 'pci_dss_4.0', 'hipa', 'iso_27001-2013', 'nist_sp_800-53'],
}

minimal = ['id', 'title', 'description', 'rationale', 'remediation', 'compliance', 'condition', 'rules']


VERSTION_COMPLIANCE_MAPPING = {
    'v8': ['nist_800_53', 'cmmc_v2.0', 'soc_2', 'hipa', 'pci_dss_4.0', 'pci_dss_3.2.1'],
    'v7': ['iso_27001-2013', 'mitre_techniques', 'mitre_tactics', 'mitre_mitigations'],
}

def sort_dict_keys(d):
    keys = ['id', 'title', 'description', 'rationale', 'remediation', 'compliance', 'condition', 'rules']
    references_index = 5
    if 'impact' in d:
        keys.insert(4, 'impact')
        references_index += 1
    if 'references' in d:
        keys.insert(references_index, 'references')


    return sorted(d, key=lambda k: keys.index(k))


def sort_dict_keys_compliance(d):
    # keys = ['cis']

    keys = ['cis', 'cis_csc_v8', 'cis_csc_v7', 'nist_sp_800-53', 'iso_27001-2013', 'cmmc_v2.0', 'hipaa', 'pci_dss_3.2.1', 'pci_dss_4.0', 'soc_2', 'mitre_techniques', 'mitre_tactics', 'mitre_mitigations']

    existing_keys = set(d.keys())

    sorted_keys = ['cis'] + sorted(existing_keys.intersection(set(keys[1:])), key=lambda k: keys.index(k))

    return sorted_keys


def values_order_by_key(policy):
    checks = policy['checks']
    failures = {}

    for check in checks:
        missing_values = []
        list_values = list(check.keys())
        if sorted(list_values) != sorted(list(set(list_values))):
            if not check['id'] in failures.keys():
                failures[check['id']] = {}

            failures[check['id']].update({"Duplicated values": list_values})

        if any(not value in policy_values_expected_order for value in list_values):
            if not check['id'] in failures.keys():
                failures[check['id']] = {}

            failures[check['id']].update({"Unexpected field": list_values})
        else:
            if sort_dict_keys(list_values) != list_values:
                if not check['id'] in failures.keys():
                    failures[check['id']] = {}
                failures[check['id']].update({"Wrong order": {
                                                "expected": sort_dict_keys(list_values),
                                                "actual": list_values
                                            }})

        compliance_values = check['compliance']
        compliance_dictionary = {}

        for compliance_value in compliance_values:
            compliance_dictionary[list(compliance_value.keys())[0]] = list(compliance_value.values())[0]

        if sort_dict_keys_compliance(compliance_dictionary) != list(compliance_dictionary.keys()):
            if not check['id'] in failures.keys():
                failures[check['id']] = {}

            failures[check['id']].update({"Wrong compliance order": {
                "expected": sort_dict_keys_compliance(compliance_dictionary),
                "actual": list(compliance_dictionary.keys())
            } })


    return failures

def get_cis_mapping():
    dirname = os.path.dirname(__file__)
    v7_mapping_file = os.path.join(dirname, '../sca_dictionary/v7.yaml')
    v8_mapping_file = os.path.join(dirname, '../sca_dictionary/v8.yaml')

    v7_mapping = {}
    v8_mapping = {}

    with open(v7_mapping_file, 'r') as file:
        v7_mapping = yaml.load(file, Loader=yaml.FullLoader)
    with open(v8_mapping_file, 'r') as file:
        v8_mapping = yaml.load(file, Loader=yaml.FullLoader)

    return {'v8': v8_mapping, 'v7': v7_mapping}


def get_compliance_values(policy_automatic_compliance_mapping, cis_compliance_mapping, cis_7, cis_8):
    compliance_values_v7 = cis_compliance_mapping.get('v7')
    compliance_values_v8 = cis_compliance_mapping.get('v8')

    expected_compliance_values = {}

    if cis_7:
        for compliance_key, compliance_value in compliance_values_v7.items():
            compliance_dictionary = {}
            if compliance_value:
                for value in compliance_value:
                    compliance_dictionary[list(value.keys())[0]] = list(value.values())[0]

            for key, value in compliance_dictionary.items():
                if compliance_key in cis_compliance_mapping['v7'] and key in policy_automatic_compliance_mapping and compliance_key in cis_7 and key in VERSTION_COMPLIANCE_MAPPING['v7']:
                    if not key in expected_compliance_values.keys():
                        expected_compliance_values[key] = []
                    expected_compliance_values[key].extend(value)

    if cis_8:
        for compliance_key, compliance_value in compliance_values_v8.items():
            compliance_dictionary = {}
            if compliance_value:
                for value in compliance_value:
                    compliance_dictionary[list(value.keys())[0]] = list(value.values())[0]


            for key, value in compliance_dictionary.items():
                if compliance_key in cis_compliance_mapping['v8'] and key in policy_automatic_compliance_mapping and compliance_key in cis_8 and key in VERSTION_COMPLIANCE_MAPPING['v8']:
                        if not key in expected_compliance_values.keys():
                            expected_compliance_values[key] = []
                        expected_compliance_values[key].extend(value)

    for key, value in expected_compliance_values.items():
        expected_compliance_values[key] = sorted(list(set(value)))

    return expected_compliance_values


def validate_cis_compliace_mapping_automatic(policy):
    policy_name = policy['policy']['id']
    cis_compliance_mapping = get_cis_mapping()
    list_of_failures = {}

    list_automatic_compliance_mapping_values = automatic_compliace_mapping_policies[policy_name]

    for check in policy['checks']:
        compliance_values = check['compliance']
        compliance_dictionary = {}

        for compliance_value in compliance_values:
            compliance_dictionary[list(compliance_value.keys())[0]] = list(compliance_value.values())[0]


        cis_8 = compliance_dictionary.get('cis_csc_v8')
        cis_7 = compliance_dictionary.get('cis_csc_v7')

        expected_compliance_values = get_compliance_values(list_automatic_compliance_mapping_values,
                                                            cis_compliance_mapping, cis_7, cis_8)
        for key,value in expected_compliance_values.items():
            same_value = value == compliance_dictionary.get(key)
            if isinstance(value, list) and isinstance(compliance_dictionary.get(key), list):
                same_value = sorted(value) == sorted(compliance_dictionary.get(key))
            if not same_value:
                if not check['id'] in list_of_failures:
                    list_of_failures[check['id']] = {}

                list_of_failures[check['id']][key] = {
                    "Expected": str(value).replace("'", ''),
                    "Current": str(compliance_dictionary.get(key)).replace("'", '')
                }

    return list_of_failures



def validate_cis_ids_in_file(policy):

    checks = policy['checks']
    first_id = checks[0]['id']
    failures = None
    list_ids = []

    for check in checks:
        list_ids.append(str(check['id']))


    expected_id_list = [str(i) for i in range(first_id, first_id + len(list_ids))]

    if expected_id_list != list_ids:
        # Get first different element
        first_wrong_id = None
        for i in range(len(list_ids)):
            if list_ids[i] != expected_id_list[i]:
                first_wrong_id = list_ids[i]
                break

        current_id_list = ' '.join(list_ids)
        expected_id_list = ' '.join(expected_id_list)
        failures = {'first_wrong_id': first_wrong_id, 'current': current_id_list, 'expected': expected_id_list}

    return failures

def validate_minimum_cis_values(policy):
    checks = policy['checks']
    failures_minimum_values = {}

    for check in checks:
        missing_values = []
        if not check.get('id'):
            missing_values.append('id')
        if not check.get('title'):
            missing_values.append('title')
        if not check.get('description'):
            missing_values.append('description')
        if not check.get('rationale'):
            missing_values.append('rationale')
        if not check.get('remediation'):
            missing_values.append('remediation')
        if not check.get('compliance'):
            missing_values.append('compliance')

        if missing_values:
            failures_minimum_values[check['id']] = {"Missing values": missing_values}

    return failures_minimum_values


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-f', '--file', metavar='<policy_list_file>', type=str, required=True,
                            default=None, help='Policy file list paths', dest='policy_file_list')

    return arg_parser.parse_args()

def get_policy_files(policy_file_list):
    with open(policy_file_list, 'r') as file:
        files = [line.rstrip() for line in file]
        return files


def get_policy_values(policy_file):
    with open(policy_file, 'r') as file:
        reader = yaml.load(file, Loader=yaml.FullLoader)
        return reader


def main():
    parameters = get_parameters()
    failures = {}

    for policy_file in get_policy_files(parameters.policy_file_list):
        try:
            policy = get_policy_values(policy_file)

            # Fields in order
            order_failures = values_order_by_key(policy)
            if order_failures:
                if not policy_file in failures:
                    failures[policy_file] = {}
                failures[policy_file]['Bad order'] = order_failures

            ## Compliance check
            compliance_failures = validate_cis_compliace_mapping_automatic(policy)
            if compliance_failures:
                if not failures.get(policy_file):
                    failures[policy_file] = {}

            for id_check, value in compliance_failures.items():
                if not id_check in failures.get(policy_file).keys():
                    failures[policy_file][id_check] = value


            ## IDS check
            values_list = []
            list_of_ids = []

            id_failures = validate_cis_ids_in_file(policy)

            if id_failures:
                if not failures.get(policy_file):
                    failures[policy_file] = {}

                failures[policy_file]['ID'] = {
                    "Description": f"Wrong CIS IDs in {policy_file}",
                    "Details": id_failures
                }

            ## Minimum values check
            minimum_values_failures = validate_minimum_cis_values(policy)
            if minimum_values_failures:
                if not failures.get(policy_file):
                    failures[policy_file] = {}

                failures[policy_file]['Minimum values'] = {
                    "Description": f"Missing minimum values in {policy_file}",
                    "Details": minimum_values_failures
                }
        except Exception as e:
            if not failures.get(policy_file):
                failures[policy_file] = {}

            failures[policy_file]['Exception'] = {
                "Description": f"Exception in {policy_file}",
                "Details": str(e)
            }

    if failures:
        yaml.dump(failures, sys.stdout, default_flow_style=False)
        exit(-1)


if __name__ == '__main__':
    main()