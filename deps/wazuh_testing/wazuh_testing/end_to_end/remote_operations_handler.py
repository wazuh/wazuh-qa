from wazuh_testing.end_to_end.regex import get_event_regex
from wazuh_testing.end_to_end.monitoring import monitoring_events
from multiprocessing.pool import ThreadPool


def launch_remote_operation(host, operation, operation_data, host_manager):
    host_os_name = host_manager.get_host_variables(host)['os'].split('_')[0]
    host_os_arch = host_manager.get_host_variables(host)['arch']

    system = host_manager.get_host_variables(host)['os_name']
    if system == 'linux':
        system = host_manager.get_host_variables(host)['os'].split('_')[0]


    if operation == 'install_package':
        package_data = operation_data['package']
        package_url = package_data[host_os_name][host_os_arch]
        host_manager.install_package(host, package_url, system)

    elif operation == 'remove_package':
        package_data = operation_data['package']
        package_name = package_data[host_os_name]
        host_manager.remove_package(host, package_name, system)

    elif operation == 'check_agent_vulnerability':
        if operation_data['parameters']['alert_indexed']:
            check_vuln_indexer(host_manager, operation_data['vulnerability_data'])
        if operation_data['parameters']['alert']:
            check_vuln_alert(host_manager, operation_data['vulnerability_data'])
        if operation_data['parameters']['api']:
            check_vuln_alert_api(host_manager, operation_data['vulnerability_data'])
        if operation_data['parameters']['state_indice']:
            check_vuln_state_index(host_manager, operation_data['vulnerability_data'])


def check_vuln_state_index(host_manager, vulnerability_data):
    pass

def check_vuln_indexer(host_manager, vulnerability_data):
    pass

def check_vuln_alert_api(host_manager, vulnerability_data):
    pass

def check_vuln_alert(host_manager, vulnerability_data):
    monitoring_data = {}

    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        host_os_arch = host_manager.get_host_variables(agent)['arch']

        agent_vulnerability_data_parameters = vulnerability_data[host_os_name][host_os_arch]
        agent_vulnerability_data_parameters['HOST_NAME'] = agent

        agent_vulnerability_data = {
            'event': 'vulnerability_alert',
            'parameters': agent_vulnerability_data_parameters
        }

        regex = get_event_regex(agent_vulnerability_data)

        monitoring_element = {
            'regex': regex,
            'path': '/var/ossec/logs/alerts/alerts.json',
            'timeout': 30,
        }

        if host_manager.get_host_variables(agent)['manager'] not in monitoring_data:
            monitoring_data[host_manager.get_host_variables(agent)['manager']] = []

        monitoring_data[host_manager.get_host_variables(agent)['manager']].append(monitoring_element)

    monitoring_events(host_manager, monitoring_data)


def launch_remote_sequential_operation_on_agent(agent, task_list, host_manager):
    if task_list:
        for task in task_list:
            task_keys = list(task.keys())
            task_values = list(task.values())
            operation, operation_data = task_keys[0], task_values[0]
            launch_remote_operation(agent, operation, operation_data, host_manager)


def launch_parallel_operations(task_list, host_manager, group='agent'):
    agents = host_manager.get_group_hosts('agent')
    parallel_configuration = [(agent, task_list, host_manager) for agent in agents]
    with ThreadPool() as pool:
        # Use the pool to map the function to the list of hosts
        pool.starmap(launch_remote_sequential_operation_on_agent, parallel_configuration)
