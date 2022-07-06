# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import ansible_runner
import pytest
import yaml
from tempfile import gettempdir

from wazuh_testing.tools.file import remove_file
from wazuh_testing import end_to_end as e2e


alerts_json = os.path.join(gettempdir(), 'alerts.json')


@pytest.fixture(scope='function')
def clean_environment(get_dashboard_credentials, request):
    """Remove the temporary file that contains the alerts and delete indices using the API.

      Args:
          credentials (dict): wazuh-indexer credentials.
          request (fixture): Provide information on the executing test function.
    """
    yield
    remove_file(alerts_json)
    e2e.delete_index_api(credentials=get_dashboard_credentials, ip_address=request.module.current_hostname)


@pytest.fixture(scope='module')
def get_dashboard_credentials(request):
    """Get wazuh-dashboard username and password.

       Returns:
            dict: wazuh-dashboard credentials.
    """
    inventory_playbook = [request.config.getoption('--inventory_path')]

    if not inventory_playbook:
        raise ValueError('Inventory not specified')

    # Get the hostname from the inventory
    hostname = [*yaml.safe_load(open(inventory_playbook[0]))['all']['hosts'].keys()][0]

    # get_inventory returns a tuple with the second element empty, that's why we access to the first element using [0]
    inventory = ansible_runner.get_inventory(action='host', host=hostname, inventories=inventory_playbook,
                                             response_format='json')[0]

    dashboard_credentials = {
        'user': inventory['dashboard_user'],
        'password': inventory['dashboard_password']
    }

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

    # Get the hostname from the inventory
    hostname = [*yaml.safe_load(open(inventory_playbook))['all']['hosts'].keys()][0]
    # Set the current hostname as an attribute of the test
    request.module.current_hostname = hostname

    # For each configuration playbook previously declared in the test, get the complete path and run it
    for playbook in getattr(request.module, 'configuration_playbooks'):
        configuration_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)
        parameters = {'playbook': configuration_playbook_path, 'inventory': inventory_playbook}

        # Add the hostname to the extravars dictionary
        parameters.update({'extravars': {'inventory_hostname': hostname}})

        # Check if the module has extra variables to pass to the playbook
        configuration_extra_vars = getattr(request.module, 'configuration_extra_vars', None)
        if configuration_extra_vars is not None:
            parameters['extravars'].update(configuration_extra_vars)

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

    # Get the hostname from the inventory
    hostname = [*yaml.safe_load(open(inventory_playbook))['all']['hosts'].keys()][0]

    # For each event generation playbook previously declared in the test, obtain the complete path and execute it.
    for playbook in getattr(request.module, 'events_playbooks'):
        events_playbook_path = os.path.join(getattr(request.module, 'test_data_path'), 'playbooks', playbook)

        parameters = {'playbook': events_playbook_path, 'inventory': inventory_playbook}

        # Add the hostname to the extravars dictionary
        parameters.update({'extravars': {'inventory_hostname': hostname}})

        # Check if the test case has extra variables to pass to the playbook and add them to the parameters in that case
        if 'extra_vars' in metadata:
            parameters['extravars'].update(metadata['extra_vars'])

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
