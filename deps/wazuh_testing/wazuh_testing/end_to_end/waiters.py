from wazuh_testing.end_to_end.monitoring import (
    generate_monitoring_logs_manager,
    monitoring_events_multihost
)
from wazuh_testing.end_to_end.wazuh_api import get_agents_id
from wazuh_testing.tools.system import HostManager


def wait_until_vd_is_updated(host_manager: HostManager) -> None:
    """
    Wait until the vulnerability data is updated for all manager hosts.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """
    monitoring_data = {}

    for manager in host_manager.get_group_hosts('manager'):
        monitoring_data = generate_monitoring_logs_manager(
            host_manager, manager, 'Starting vulnerability scan', 800
        )

    monitoring_events_multihost(host_manager, monitoring_data)


def wait_until_vuln_scan_agents_finished(host_manager: HostManager) -> None:
    """
    Wait until vulnerability scans for all agents are finished.

    Args:
        host_manager (HostManager): Host manager instance to handle the environment.
    """
    for agent in host_manager.get_group_hosts('agent'):
        manager_host = host_manager.get_host_variables(agent)['manager']
        agents_id = get_agents_id(host_manager)
        agent_id = agents_id.get(agent, '')
        finished_scan_pattern = rf"Finished vulnerability assessment for agent '{agent_id}'"
        
        monitoring_data = generate_monitoring_logs_manager(
            host_manager, manager_host, finished_scan_pattern, 700
        )

        monitoring_events_multihost(host_manager, monitoring_data)
