def control_environment(host_manager, operation, group_list):
    for group in group_list:
        for host in host_manager.get_group_hosts(group):
            host_manager.handle_wazuh_services(host, operation)