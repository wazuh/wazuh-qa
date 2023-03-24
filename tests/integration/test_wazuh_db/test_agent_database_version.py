import pytest

from wazuh_testing.modules import TIER0, LINUX, SERVER
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools import agent_simulator as ag
from wazuh_testing.tools.wazuh_manager import remove_all_agents

# Marks
pytestmark = [TIER0, LINUX, SERVER]

# Variables
expected_database_version = '11'


# Fixtures
@pytest.fixture()
def remove_agents():
    yield
    remove_all_agents('manage_agents')


# Tests
def test_agent_database_version(restart_wazuh_daemon, remove_agents):
    '''
    description: Check that the agent database version is the expected one. To do this, it performs a query to the agent
                 database that gets the database version.

    test_phases:
        - setup:
            - Restart wazuh-manager service.
        - test:
            - Get the version of the manager database through the socket
            - Get the version of the agent database through the socket
            - Check that the manager database version is the expected one.
            - Check that the agent database version is the expected one.

    wazuh_min_version: 4.6.0

    parameters:
        - restart_wazuh_daemon:
            type: fixture
            brief: Restart the wazuh service.

    assertions:
        - Verify that database version is the expected one.

    expected_output:
        - Database version: 11

    tags:
        - wazuh_db
        - wdb_socket
    '''
    agents = ag.create_agents(1, 'localhost')
    ag.connect(agents[0])

    manager_version = query_wdb("agent 0 sql SELECT value FROM metadata WHERE key='db_version'")[0]['value']
    agent_version = query_wdb(f"agent {agents[0].id} sql SELECT value FROM metadata WHERE key='db_version'")[0]['value']

    assert manager_version == expected_database_version, 'The manager database version is not the expected one. \n' \
                                                         f'Expected version: {expected_database_version}\n'\
                                                         f'Obtained version: {manager_version}'
    assert agent_version == expected_database_version, 'The agent database version is not the expected one. \n' \
                                                       f'Expected version: {expected_database_version}\n'\
                                                       f'Obtained version: {agent_version}'
