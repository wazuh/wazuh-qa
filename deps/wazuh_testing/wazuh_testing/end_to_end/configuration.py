from multiprocessing.pool import ThreadPool
import xml.dom.minidom
from ansible.parsing.dataloader import DataLoader

from wazuh_testing.end_to_end import configuration_filepath_os
from wazuh_testing.tools.configuration import set_section_wazuh_conf


# Configuration methods
def backup_configurations(host_manager):
    backup_configurations = {}
    for host in host_manager.get_group_hosts('all'):
        host_variables = host_manager.get_host_variables(host)
        host_os = host_variables['os_name']
        configuration_file_path = configuration_filepath_os[host_os]
        current_configuration = host_manager.get_file_content(str(host), configuration_file_path)
        backup_configurations[str(host)] = current_configuration
    return backup_configurations


def restore_backup(host_manager, backup_configurations):
    for host in host_manager.get_group_hosts('all'):
        host_variables = host_manager.get_host_variables(host)
        host_os = host_variables['os_name']
        configuration_file_path = configuration_filepath_os[host_os]
        host_manager.modify_file_content(str(host), configuration_file_path, backup_configurations[str(host)])


def configure_environment(host_manager, configurations):
    def configure_host(host, host_configuration_role):
        print(f"Configure {host}")
        host_os = host_manager.get_host_variables(host)['os_name']
        configuration_file_path = configuration_filepath_os[host_os]

        host_groups = host_manager.get_host_groups(host)
        host_configuration = None
        if 'manager' in host_groups:
            host_configuration = host_configuration_role['manager']
        elif 'agent' in host_groups:
            host_configuration = host_configuration_role['agent']

        current_configuration = host_manager.get_file_content(str(host), configuration_file_path)
        print(current_configuration)
        new_configuration = set_section_wazuh_conf(host_configuration[0].get('sections'), current_configuration.split("\n"))

        new_configuration = [line for line in new_configuration if line.strip() != ""]
        dom = xml.dom.minidom.parseString(''.join(new_configuration))
        new_configuration = "\n".join(dom.toprettyxml().split("\n")[1:])

        host_manager.modify_file_content(str(host), configuration_file_path, new_configuration)


    loader = DataLoader()
    configure_environment_parallel_map = [ (host, configurations) for host in host_manager.get_group_hosts('all')]

    with ThreadPool() as pool:
        pool.starmap(configure_host, configure_environment_parallel_map)
