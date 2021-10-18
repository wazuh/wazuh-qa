import os
import time
import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import read_yaml
from authd import create_authd_request, validate_authd_response, AUTHD_KEY_REQUEST_TIMEOUT

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc', 'client.keys')

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'force_options_configuration.yaml')

configurations = load_wazuh_configurations(configurations_path, __name__)
tests = read_yaml(os.path.join(test_data_path, 'key_mismatch.yaml'))

"""
tests2 = read_yaml(os.path.join(test_data_path, 'after_registration_time.yaml'))
tests3 = read_yaml(os.path.join(test_data_path, 'disconnected_time.yaml'))

for i in range(len(tests2)):
    tests.append(tests2[i])

for i in range(len(tests3)):
    tests.append(tests3[i])
"""

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2'), (WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-authd', None, True), ('wazuh-db', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

configuration_ids = ['authd_force_options']
test_case_ids = [f"{test_case['name']}" for test_case in tests]

# Functions
def get_temp_force_config(param):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(test_data_path, 'temp.yaml')
    with open(configurations_path, 'r') as conf_file:
        force_conf = {'force': {'elements': []}}
        for elem in param:
            if elem == 'disconnected_time':
                disconnected_time_conf = {'disconnected_time':{'value': 0, 'attributes':[{'enabled':'no'}]}}
                disconnected_time_conf['disconnected_time']['value'] = param[elem]['value']
                disconnected_time_conf['disconnected_time']['attributes'][0]['enabled'] = param[elem]['attributes'][0]['enabled']
                force_conf['force']['elements'].append(disconnected_time_conf)
            else:
                force_conf['force']['elements'].append({elem: {'value': param[elem]}})
        temp_conf_file = yaml.safe_load(conf_file)
        temp_conf_file[0]['sections'][0]['elements'].append(force_conf)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


# Fixtures

@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='function', params=tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param


@pytest.fixture(scope='function')
def override_authd_force_conf(get_current_test_case, request):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})
    #parse_configuration_string(configuration)
    # Configuration for testing
    temp = get_temp_force_config(configuration)
    conf = load_wazuh_configurations(temp, test_name, )
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])
    # Set new configuration
    write_wazuh_conf(test_config)


@pytest.fixture(scope='function')
def insert_pre_existent_agents(get_current_test_case, request):
    agents = get_current_test_case.get('pre_existent_agents', [])
    time_now = int(time.time())
    wdb_sock = receiver_sockets[1]
    try:
        keys_file = open(CLIENT_KEYS_PATH, 'w')
    except IOError as exception:
        raise exception

    # Clean agents from DB
    command = f'global sql DELETE FROM agent WHERE id != 0'
    wdb_sock.send(command, size=True)
    response = wdb_sock.receive(size=True).decode()
    data = response.split(" ", 1)
    assert data[0] == 'ok', f'Unable to clean agents'

    for agent in agents:
        if 'id' in agent:
            id = agent['id']
        else:
            id = '001'

        if 'name' in agent:
            name = agent['name']
        else:
            name = f'TestAgent{id}'

        if 'ip' in agent:
            ip = agent['ip']
        else:
            ip = 'any'

        if 'key' in agent:
            key = agent['key']
        else:
            key = 'TopSecret'

        if 'connection_status' in agent:
            connection_status = agent['connection_status']
        else:
            connection_status = 'never_connected'

        if 'disconnection_time' in agent and 'delta' in agent['disconnection_time']:
            disconnection_time = time_now + agent['disconnection_time']['delta']
        elif 'disconnection_time' in agent and 'value' in agent['disconnection_time']:
            disconnection_time = agent['disconnection_time']['value']
        else:
            disconnection_time = 0

        if 'registration_time' in agent and 'delta' in agent['registration_time']:
            registration_time = time_now + agent['registration_time']['delta']
        elif 'registration_time' in agent and 'value' in agent['registration_time']:
            registration_time = agent['registration_time']['value']
        else:
            registration_time = time_now

        # Write agent in client.keys
        keys_file.write(f'{id} {name} {ip} {key}\n')

        # Write agent in global.db
        command = f'global insert-agent {{"id":{id},"name":"{name}","ip":"{ip}","date_add":{registration_time},\
                  "connection_status":"{connection_status}", "disconnection_time":"{disconnection_time}"}}'
        wdb_sock.send(command, size=True)
        response = wdb_sock.receive(size=True).decode()
        data = response.split(" ", 1)
        assert data[0] == 'ok', f'Unable to add agent {id}'

    keys_file.close()


# Tests

def test_authd_force_options(configure_environment, configure_sockets_environment, connect_to_sockets_module,
                             stop_authd_function, override_authd_force_conf, insert_pre_existent_agents,
                             restart_authd_function, wait_for_authd_startup_function,
                             connect_to_sockets_function, get_current_test_case, tear_down):

    authd_sock = receiver_sockets[0]

    for stage in get_current_test_case['test_case']:
        # Reopen socket (socket is closed by manager after sending message with client key)
        authd_sock.open()

        authd_sock.send(create_authd_request(stage['input']), size=False)
        timeout = time.time() + AUTHD_KEY_REQUEST_TIMEOUT
        response = ''
        while response == '':
            response = authd_sock.receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        validate_authd_response(response, stage['output'])
