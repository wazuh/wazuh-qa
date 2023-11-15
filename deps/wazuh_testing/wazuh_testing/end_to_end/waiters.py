from wazuh_testing.end_to_end.monitoring import generate_monitoring_logs_manager, monitoring_events
from wazuh_testing.end_to_end.wazuh_api import get_agents_id



def wait_until_vd_is_updated(host_manager):
    monitoring_data = {}
    for manager in host_manager.get_group_hosts('manager'):
        monitoring_data = generate_monitoring_logs_manager(host_manager, manager, 'Starting vulnerability scan', 600)

    monitoring_events(host_manager, monitoring_data)


def wait_until_vuln_scan_agents_finished(host_manager):
    for agent in host_manager.get_group_hosts('agent'):
        manager_host = host_manager.get_host_variables(agent)['manager']
        agents_id = get_agents_id(host_manager)
        monitoring_data = generate_monitoring_logs_manager(host_manager, manager_host,rf"Finished vulnerability assessment for agent '{agents_id[agent]}'", 30)
        monitoring_events(host_manager, monitoring_data)
