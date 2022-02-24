
import os
import time
import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools.services import delete_dbs

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_file = os.path.join(test_data_path, 'sync_agent_groups_get.yaml')
module_tests = []
with open(messages_file) as f:
    module_tests.append((yaml.safe_load(f), messages_file.split('_')[0]))

log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets= None  # Set in the fixtures
agents = ['agent1', 'agent2']


#Fixtures
@pytest.fixture(scope='module')
def remove_database(request):
    yield
    delete_dbs()


@pytest.fixture(scope='module')
def pre_insert_agents():
    for i in range(len(agents)):
        id = i + 1
        name = 'Agent-test' + str(id)
        date = time.time()
        command = f'global insert-agent {{"id":{id},"name":"{name}","date_add":{date}}}'
        results = query_wdb(command)
        assert results == 'ok'

        command = f'global set-agent-groups {{"mode":"append","sync_status":"syncreq","source":"remote","data":[{{"id":{id},"groups":["Test_group{id}"]}}]}}'
        results = query_wdb(command)
        assert results == 'ok'


# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_set_agent_groups(remove_database, configure_sockets_environment, connect_to_sockets_module, test_case, pre_insert_agents):
    
    case_data = test_case[0]
    output = case_data["output"]

    if 'pre_input' in case_data:
        query_wdb(case_data['pre_input'])

    response = query_wdb(case_data["input"])
    
    # validate response
    assert str(response) == output

    