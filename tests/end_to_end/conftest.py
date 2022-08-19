# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import ansible_runner
import pytest
import json
from tempfile import gettempdir

from wazuh_testing.tools.file import remove_file
from wazuh_testing import end_to_end as e2e


alerts_json = os.path.join(gettempdir(), 'alerts.json')
suite_path = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope='session', autouse=True)
def validate_environments(request):
    """Fixture with session scope to validate the environments before run the E2E tests.

    This phase is divided into 4 steps:
        Step 1: Collect the data related to the selected tests that will be executed.
        Step 2: Generate a playbook containing cross-checks for selected tests.
        Step 3: Run the generated playbook.
        Step 4: Generate a test-specific playbook to validate the environment required by that test, then execute that
                playbook. This will run one validation for each selected test set.
                To add specific validation tasks to a test its only necessary to add a new jinja2 template inside the
                `playbooks` folder in the test suite. E.g:
                test_basic_cases/test_fim/test_fim_linux/data/playbooks/validation.j2
                (See end_to_end/data/validation_templates for a guide to create the file)

    Args:
        request (fixture):  Gives access to the requesting test context.
    """
    collected_items = request.session.items
    roles_path = request.config.getoption('--roles-path')
    inventory_path = request.config.getoption('--inventory_path')
    environment_file = os.path.join(suite_path, 'data', 'env_requirements.json')
    environment_metadata = json.load(open(environment_file))
    playbook_generator = os.path.join(suite_path, 'data', 'validation_playbooks', 'generate_general_play.yaml')
    playbook_template = os.path.join(suite_path, 'data', 'validation_templates', 'general_validation.j2')
    general_playbook = os.path.join(suite_path, 'data', 'validation_playbooks', 'general_validation.yaml')

    if not inventory_path:
        raise ValueError('Inventory not specified')

    #--------------------------------------- Step 1: Prepare the necessary data ----------------------------------------
    # Get the path of the tests from collected items.
    collected_paths = [item.fspath for item in collected_items]
    # Remove duplicates caused by the existence of 2 or more test cases
    collected_paths = list(dict.fromkeys(collected_paths))
    test_suites_paths = []
    manager_instances = []
    agent_instances = []

    for path in collected_paths:
        # Remove the name of the file from the path
        path = str(path).rsplit('/', 1)[0]
        # Add the test suite path
        test_suites_paths.append(path)
        # Get the test suite name
        test_suite_name = path.split('/')[-1:][0]
        # Save the test environment metadata
        manager_instances.append(environment_metadata[test_suite_name]['manager']['instances'])
        agent_instances.append(environment_metadata[test_suite_name]['agent']['instances'])

    # Get the largest number of manager/agent instances
    num_of_managers = max(manager_instances)
    num_of_agents = max(agent_instances)
    #-------------------------------------------------- End of Step 1 --------------------------------------------------

    #---------------------- Step 2: Run the playbook to generate the general validation playbook -----------------------
    gen_parameters = {
        'playbook': playbook_generator, 'inventory': inventory_path,
        'extravars': {
            'template_path': playbook_template, 'dest_path': general_playbook,
            'num_of_managers': num_of_managers, 'num_of_agents': num_of_agents
        }
    }
    ansible_runner.run(**gen_parameters)
    #-------------------------------------------------- End of Step 2 --------------------------------------------------

    #----------------------------------- Step 3: Run the general validation playbook -----------------------------------
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
        raise Exception(f"The general validations have failed. Please check that the environments meet the expected "
                        'requirements.')
    #-------------------------------------------------- End of Step 3 --------------------------------------------------

    #------------------------------------ Step 4: Execute test-specific validations ------------------------------------
    playbook_generator = os.path.join(suite_path, 'data', 'validation_playbooks', 'generate_test_specific_play.yaml')
    playbook_template = os.path.join(suite_path, 'data', 'validation_templates', 'test_specific_validation.j2')

    for path in test_suites_paths:
        validation_template = os.path.join(path, 'data', 'playbooks', 'validation.j2')
        validation_template = validation_template if os.path.exists(validation_template) else ''
        # Define the path where the resulting playbook will be stored
        validation_playbook = os.path.join(path, 'data', 'playbooks', 'validation.yaml')

        # Get distros by instances type
        test_suite_name = path.split('/')[-1:][0]
        target_hosts = []
        distros = {"manager": [], "agent": []}
        for key in environment_metadata[test_suite_name]:
            if environment_metadata[test_suite_name][key]['instances'] > 0:
                # Save manager/agent distros for the current test
                distros[key] = environment_metadata[test_suite_name][key]['distros']
                # Add the target host to the list (following the standard host name: "<distro>-<type>*")
                target_hosts.extend([distro.lower() + f"-{key}*" for distro in distros[key]])

        # Generate test_specific validation playbook
        gen_parameters = {
            'playbook': playbook_generator, 'inventory': inventory_path, 'envvars': {'ANSIBLE_ROLES_PATH': roles_path},
            'extravars': {
                'template_path': playbook_template, 'dest_path': validation_playbook,
                'num_of_managers': num_of_managers, 'num_of_agents': num_of_agents,
                'validation_template': validation_template, 'target_hosts': ','.join(target_hosts),
                'manager_distros': distros['manager'], 'agent_distros': distros['agent']
            }
        }
        ansible_runner.run(**gen_parameters)

        # Run test_specific validation playbook
        parameters = {
            'playbook': validation_playbook, 'inventory': inventory_path, 'envvars': {'ANSIBLE_ROLES_PATH': roles_path}
        }
        validation_runner = ansible_runner.run(**parameters)
        # Remove the generated playbook
        remove_file(validation_playbook)

        # If the validation phase has failed, then abort the execution finishing with an error. Else, continue.
        if validation_runner.status == 'failed':
            raise Exception(f"The validation phase of {test_suite_name} has failed. Please check that the environments "
                            'meet the expected requirements.')
    #-------------------------------------------------- End of Step 4 --------------------------------------------------


@pytest.fixture(scope='function')
def clean_alerts_index(get_dashboard_credentials):
    """Remove the temporary file that contains the alerts and delete indices using the API.

      Args:
          credentials (dict): wazuh-indexer credentials.
    """
    yield
    remove_file(alerts_json)
    e2e.delete_index_api(credentials=get_dashboard_credentials)


@pytest.fixture(scope='module')
def get_dashboard_credentials(request):
    """Get wazuh-dashboard username and password.

       Returns:
            dict: wazuh-dashboard credentials.
    """
    inventory_playbook = [request.config.getoption('--inventory_path')]

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    inventory = ansible_runner.get_inventory(action='host', inventories=inventory_playbook, response_format='json',
                                             host='wazuh-manager')

    # Inventory is a tuple, with the second value empty, so we must access inventory[0]
    dashboard_credentials = {'user': inventory[0]['dashboard_user'], 'password': inventory[0]['dashboard_password']}

    yield dashboard_credentials


@pytest.fixture(scope='module')
def configure_environment(request):
    """Fixture to configure environment.

    Execute the configuration playbooks declared in the test to configure the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    inventory_playbook = request.config.getoption('--inventory_path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    # For each configuration playbook previously declared in the test, get the complete path and run it
    for playbook in getattr(request.module, 'configuration_playbooks'):
        configuration_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)
        parameters = {'playbook': configuration_playbook_path, 'inventory': inventory_playbook}

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

            parameters = {'playbook': teardown_playbook_path, 'inventory': inventory_playbook}

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
    inventory_playbook = request.config.getoption('--inventory_path')

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    # For each event generation playbook previously declared in the test, obtain the complete path and execute it.
    for playbook in getattr(request.module, 'events_playbooks'):
        events_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

        parameters = {'playbook': events_playbook_path, 'inventory': inventory_playbook}
        # Check if the test case has extra variables to pass to the playbook and add them to the parameters in that case
        if 'extra_vars' in metadata:
            parameters.update({'extravars': metadata['extra_vars']})

        ansible_runner.run(**parameters)


def pytest_addoption(parser):
    parser.addoption(
        '--inventory_path',
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
        default=os.path.join(suite_path, 'roles'),
        type=str,
        help='Ansible roles path.',
    )
