# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import ansible_runner
import pytest


suite_path = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope='function')
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


def pytest_addoption(parser):
    """Method to add some options to launch tests.

    Args:
        parser (argparse.ArgumentParser): Parser object to add the options.
    """
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
