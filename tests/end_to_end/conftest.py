# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import ansible_runner
import pytest
from tempfile import gettempdir

from wazuh_testing.tools.file import remove_file
from wazuh_testing import end_to_end as e2e


alerts_json = os.path.join(gettempdir(), 'alerts.json')


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
