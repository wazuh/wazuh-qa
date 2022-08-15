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

    This phase is divided in 4 steps:
        Step 1: Collect the data related with the selected tests that will be executed.
        Step 2: Generate a playbook with general validations containing cross-checks for selected tests.
        Step 3: Run the generated playbook.
        Step 4: Execute test-specific validations (if any). It will run one validation for each selected test set.

    Args:
        request (fixture):  Gives access to the requesting test context.
    """
    collected_items = request.session.items
    roles_path = request.config.getoption('--roles-path')
    inventory_path = request.config.getoption('--inventory_path')
    environment_file = os.path.join(suite_path, 'data', 'environment.json')
    environment_metadata = json.load(open(environment_file))
    playbook_generator = os.path.join(suite_path, 'data', 'generate_general_play.yaml')
    playbook_template = os.path.join(suite_path, 'data', 'validation_template.j2')
    general_playbook = os.path.join(suite_path, 'data', 'general_validation.yaml')

    if not inventory_path:
        raise ValueError('Inventory not specified')

    # -------------------------- Step 1: Prepare the necessary data ----------------
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
        # Save the test environment metadata in lists
        manager_instances.append(environment_metadata[test_suite_name]['managers'])
        agent_instances.append(environment_metadata[test_suite_name]['agents'])

    # Get the largest number of manager/agent instances
    num_of_managers = max(manager_instances)
    num_of_agents = max(agent_instances)
    # -------------------------- End of Step 1 -------------------------------------

    # ---- Step 2: Run the playbook to generate the general validation playbook ----
    parameters = {
        'playbook': playbook_generator, 'inventory': inventory_path,
        'extravars': {
            'template_path': playbook_template, 'dest_path': general_playbook,
            'num_of_managers': num_of_managers, 'num_of_agents': num_of_agents
        }
    }
    ansible_runner.run(**parameters)
    # -------------------------- End of Step 2 -------------------------------------

    # -------------------- Step 3: Run the general validation playbook -------------
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
        raise Exception(f"The general validations have failed. Please check that the environments meet the expected " \
                        'requirements.')
    # -------------------------- End of Step 3 -------------------------------------

    # Step 4: Execute test-specific validations (if any)
    for path in test_suites_paths:
        validation_playbook = os.path.join(path, 'data', 'playbooks', 'validation.yaml')

        if os.path.exists(validation_playbook):
            # Set Ansible parameters
            parameters = {
                'playbook': validation_playbook,
                'inventory': inventory_path,
                'envvars': {'ANSIBLE_ROLES_PATH': roles_path}
            }
            # Run the validations of the test suite.
            validation_runner = ansible_runner.run(**parameters)

            # If the validation phase has failed, then abort the execution finishing with an error. Else, continue.
            if validation_runner.status == 'failed':
                raise Exception(f"The validation phase of {{ path }} has failed. Please check that the environments " \
                                'meet the expected requirements.')
    # -------------------------- End of Step 4 -------------------------------------


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
