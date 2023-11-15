from wazuh_testing.end_to_end import logs_filepath_os


def truncate_agents_logs(host_manager):
    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os_name']
        host_manager.truncate_file(agent, logs_filepath_os[host_os_name])

def truncate_managers_logs(host_manager):
    for agent in host_manager.get_group_hosts('manager'):
        host_os_name = host_manager.get_host_variables(agent)['os_name']
        host_manager.truncate_file(agent, logs_filepath_os[host_os_name])

def truncate_logs(host_manager):
    # for manager in host_manager.get_group_hosts('manager'):
    #     host_manager.truncate_file(manager, '/var/ossec/logs/alerts/alerts.json')
    truncate_managers_logs(host_manager)
    truncate_agents_logs(host_manager)
