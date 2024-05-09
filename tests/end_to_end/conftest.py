# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import ansible_runner
import pytest
import json
import yaml

from wazuh_testing.tools.file import remove_file
from wazuh_testing import end_to_end as e2e


suite_path = os.path.dirname(os.path.realpath(__file__))


def get_target_hosts_and_distros(test_suite_name, target_distros={'manager': [], 'agent': []}, target_hosts=[]):
    environment_file = os.path.join(suite_path, 'data', 'env_requirements.json')
    environment_metadata = json.load(open(environment_file))

    for key in environment_metadata[test_suite_name]:
        if environment_metadata[test_suite_name][key]['instances'] > 0:
            # Save manager/agent distros
            target_distros[key].extend(environment_metadata[test_suite_name][key]['distros'])
            # Add the target host to the list (following the standard host name: "<distro>-<type>*")
            target_hosts.extend([distro.lower() + f"-{key}" for distro in target_distros[key]])
    # Remove duplicates
    target_hosts = list(dict.fromkeys(target_hosts))
    target_distros['manager'] = list(dict.fromkeys(target_distros['manager']))
    target_distros['agent'] = list(dict.fromkeys(target_distros['agent']))

    return target_hosts, target_distros


def validate_inventory(inventory_path, target_hosts):
    """Check if the Ansible inventory follows our standard defined in the README.md file, inside the E2E suite.

    This function checks:
        1. If the groups/subgroups in the inventory are in our list of valid groups.
        2. If the hostnames follow our standard (<os>-<wazuh-installation-type>)

    Args:
        inventory_path (str): Path to Ansible inventory.
        target_hosts (list[str]): List of valid hosts for the selected tests.
    """
    inventory_dict = yaml.safe_load(open(inventory_path))
    inventory_hosts = []
    missing_hosts = []

    for group in inventory_dict:
        # Collect hosts from inventory
        if 'hosts' in inventory_dict[group]:
            inventory_hosts.extend([hostname for hostname in inventory_dict[group]['hosts']])
        try:
            # Collect hosts from inventory subgroups (if any)
            subgroups = inventory_dict[group]['children']
            for subgroup in subgroups:
                inventory_hosts.extend([hostname for hostname in subgroups[subgroup]['hosts']])
        except KeyError:
            # Do not throw an exception if the group has no subgroups within it
            pass

    for host in target_hosts:
        if host not in inventory_hosts:
            missing_hosts.extend([host])
    if missing_hosts != []:
        readme_file = '[README.md](https://github.com/wazuh/wazuh-qa/blob/master/tests/end_to_end/README.md)'
        raise Exception(f"Not all the hosts required to run the tests are present in the inventory.\n"
                        f"Hosts in the inventory: {inventory_hosts}\n"
                        f"Expected hosts: {target_hosts}\n"
                        f"Missing hosts: {missing_hosts}\n"
                        f"Read the {readme_file} file inside the E2E suite to build a valid inventory.")


@pytest.fixture(scope='session')
def validate_environments(request):
    """Fixture with session scope to validate the environments before run the E2E tests.

    This phase is divided into 4 steps:
        Step 1: Collect the data related to the selected tests that will be executed.
        Step 2: Check the Ansible inventory.
        Step 3: Generate a playbook containing cross-checks for selected tests.
        Step 4: Run the generated playbook.

    Args:
        request (fixture):  Gives access to the requesting test context.
    """
    collected_items = request.session.items
    roles_path = request.config.getoption('--roles-path')
    inventory_path = request.config.getoption('--inventory-path')
    playbook_generator = os.path.join(suite_path, 'data', 'validation_playbooks', 'generate_general_play.yaml')
    playbook_template = os.path.join(suite_path, 'data', 'validation_templates', 'general_validation.j2')
    general_playbook = os.path.join(suite_path, 'data', 'validation_playbooks', 'general_validation.yaml')

    if not inventory_path:
        raise ValueError('Inventory not specified')

    # --------------------------------------- Step 1: Prepare the necessary data ---------------------------------------
    test_suites_paths = []
    target_hosts, target_distros = [], {'manager': [], 'agent': []}
    # Get the path of the tests from collected items.
    collected_paths = [item.fspath for item in collected_items]
    # Remove duplicates caused by the existence of 2 or more test cases
    collected_paths = list(dict.fromkeys(collected_paths))

    for path in collected_paths:
        # Remove the name of the file from the path
        path = str(path).rsplit('/', 1)[0]
        # Add the test suite path
        test_suites_paths.append(path)
        # Get the test suite name
        test_suite_name = path.split('/')[-1:][0]
        # Set target hosts and distros
        target_hosts, target_distros = get_target_hosts_and_distros(test_suite_name, target_distros, target_hosts)
    # -------------------------------------------------- End of Step 1 -------------------------------------------------

    # -------------------------------------- Step 2: Check the Ansible inventory ---------------------------------------
    validate_inventory(inventory_path, target_hosts)
    # -------------------------------------------------- End of Step 2 -------------------------------------------------

    # ---------------------- Step 3: Run the playbook to generate the general validation playbook ----------------------
    gen_parameters = {
        'playbook': playbook_generator, 'inventory': inventory_path,
        'extravars': {
            'template_path': playbook_template,
            'dest_path': general_playbook,
            'target_hosts': ','.join(target_hosts),
            'manager_distros': target_distros['manager'],
            'agent_distros': target_distros['agent'],
        }
    }
    ansible_runner.run(**gen_parameters)
    # -------------------------------------------------- End of Step 3 -------------------------------------------------

    # ----------------------------------- Step 4: Run the general validation playbook ----------------------------------
    parameters = {
        'playbook': general_playbook,
        'inventory': inventory_path,
        'envvars': {'ANSIBLE_ROLES_PATH': roles_path}
    }
    general_validation_runner = ansible_runner.run(**parameters)
    # Remove the generated playbook
    remove_file(general_playbook)
    # If the general validations have failed, then abort the execution finishing with an error. Else, continue.
    if general_validation_runner.status == 'failed':
        # Collect inventory_hostnames with errors
        hosts_with_errors = [key for key in general_validation_runner.stats['failures']]
        # Collect list of errors
        errors = []
        errors.extend([general_validation_runner.get_fact_cache(host)['phase_results'] for host in hosts_with_errors])
        errors = ''.join(errors)
        # Raise the exception with errors details
        raise Exception(f"The general validations have failed. Please check that the environments meet the expected "
                        f"requirements. Result:\n{errors}")
    # -------------------------------------------------- End of Step 4 -------------------------------------------------


@pytest.fixture(scope='module')
def run_specific_validations(request):
    """Fixture with module scope to validate the environment of an specific tests with specific validation tasks.

    Execute a test-specific playbook (if any). This will run one validation playbook for each test module.

    Args:
        request (fixture):  Gives access to the requesting test context.
    """
    roles_path = request.config.getoption('--roles-path')
    inventory_path = request.config.getoption('--inventory-path')
    test_suite_path = os.path.dirname(request.fspath)
    test_suite_name = test_suite_path.split('/')[-1:][0]
    target_hosts, target_distros = get_target_hosts_and_distros(test_suite_name)
    validation_playbook = os.path.join(test_suite_path, 'data', 'playbooks', 'validation.yaml')

    # Run test-specific validation playbook (if any)
    if os.path.exists(validation_playbook):
        parameters = {
            'playbook': validation_playbook, 'inventory': inventory_path,
            'envvars': {'ANSIBLE_ROLES_PATH': roles_path},
            'extravars': {
                'target_hosts': ','.join(target_hosts),
                'manager_distros': target_distros['manager'],
                'agent_distros': target_distros['agent'],
            }
        }
        validation_runner = ansible_runner.run(**parameters)

        # If the validation phase has failed, then abort the execution finishing with an error. Else, continue.
        if validation_runner.status == 'failed':
            raise Exception(f"The validation phase of {test_suite_name} has failed. Please check that the "
                            'environments meet the expected requirements.')


@pytest.fixture(scope='function')
def clean_alerts_index(get_indexer_credentials, get_manager_ip):
    """Remove the temporary file that contains the alerts and delete indices using the API.

      Args:
          credentials (dict): wazuh-indexer credentials.
    """
    yield
    remove_file(e2e.fetched_alerts_json_path)
    e2e.delete_index_api(credentials=get_indexer_credentials, ip_address=get_manager_ip)


@pytest.fixture(scope='module')
def get_indexer_credentials(request):
    """Get wazuh-indexer username and password.

       Returns:
            dict: wazuh-indexer credentials.
    """
    inventory_playbook = request.config.getoption('--inventory-path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    inventories = [inventory_playbook]

    inventory_data = ansible_runner.get_inventory(action='host', inventories=inventories, response_format='json',
                                                  host='indexer')

    # inventory_data is a tuple, with the second value empty, so we must access inventory[0]
    indexer_credentials = {'user': inventory_data[0]['indexer_user'],
                           'password': inventory_data[0]['indexer_password']}

    yield indexer_credentials


@pytest.fixture(scope='module')
def configure_environment(request):
    """Fixture to configure environment.

    Execute the configuration playbooks declared in the test to configure the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    inventory_playbook = request.config.getoption('--inventory-path')
    roles_path = request.config.getoption('--roles-path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    # For each configuration playbook previously declared in the test, get the complete path and run it
    for playbook in getattr(request.module, 'configuration_playbooks'):
        configuration_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)
        parameters = {'playbook': configuration_playbook_path,
                      'inventory': inventory_playbook,
                      'envvars': {'ANSIBLE_ROLES_PATH': roles_path}}

        # Check if the module has extra variables to pass to the playbook
        configuration_extra_vars = getattr(request.module, 'configuration_extra_vars', None)
        if configuration_extra_vars is not None:
            parameters.update({'extravars': configuration_extra_vars})

        ansible_runner.run(**parameters)

    yield

    teardown_playbooks = getattr(request.module, 'teardown_playbooks')

    # Execute each playbook for the teardown
    if teardown_playbooks is not None:
        for playbook in teardown_playbooks:
            teardown_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

            parameters = {'playbook': teardown_playbook_path,
                          'inventory': inventory_playbook,
                          'envvars': {'ANSIBLE_ROLES_PATH': roles_path}}

            # Check if the module has extra variables to pass to the playbook
            configuration_extra_vars = getattr(request.module, 'configuration_extra_vars', None)
            if configuration_extra_vars is not None:
                parameters.update({'extravars': configuration_extra_vars})

            ansible_runner.run(**parameters)


@pytest.fixture(scope='function')
def generate_events(request, metadata):
    """Fixture to generate events.

    Execute the playbooks declared in the test to generate events.
    Args:
        request (fixture): Provide information on the executing test function.
        metadata (dict): Dictionary with test case metadata.
    """
    inventory_playbook = request.config.getoption('--inventory-path')
    roles_path = request.config.getoption('--roles-path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    # For each event generation playbook previously declared in the test, obtain the complete path and execute it.
    for playbook in getattr(request.module, 'events_playbooks'):
        events_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

        parameters = {'playbook': events_playbook_path,
                      'inventory': inventory_playbook,
                      'envvars': {'ANSIBLE_ROLES_PATH': roles_path}}
        # Check if the test case has extra variables to pass to the playbook and add them to the parameters in that case
        if 'extra_vars' in metadata:
            parameters.update({'extravars': metadata['extra_vars']})

        ansible_runner.run(**parameters)


@pytest.fixture(scope='module')
def get_manager_ip(request):
    """Get manager IP.

       Returns:
            str: Manager IP.
    """
    inventory_playbook = request.config.getoption('--inventory-path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    inventories = [inventory_playbook]

    inventory_data = ansible_runner.get_inventory(action='host', inventories=inventories, response_format='json',
                                                  host='manager')

    # inventory_data is a tuple, with the second value empty, so we must access inventory[0]
    manager_ip = inventory_data[0]['ansible_host']

    yield manager_ip


def pytest_addoption(parser):
    parser.addoption(
        '--inventory-path',
        action='store',
        metavar='INVENTORY_PATH',
        default=None,
        type=str,
        help='Inventory path',
    )

    parser.addoption(
        '--roles-path',
        action='store',
        metavar='ROLES_PATH',
        default=os.path.join(suite_path, 'data', 'ansible_roles'),
        type=str,
        help='Ansible roles path.',
    )
    parser.addoption(
        '--enable-modulesd-debug',
        action='store_true',
        default=False,
        help='Enable modulesd debug mode. Default: False',
    )
    parser.addoption(
        '--gather-evidences-when-passed',
        action='store_true',
        default=False,
        help='Enable gather evidences when passed. Default: False',
    )
    parser.addoption(
        '--enable-verbose-evidences',
        action='store_true',
        default=False,
        help='Enable verbose evidences. Default: False',
    )
