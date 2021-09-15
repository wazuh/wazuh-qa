import os

from time import sleep
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_instance import AnsibleInstance
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_inventory import AnsibleInventory
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_local_package import WazuhLocalPackage
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_s3_package import WazuhS3Package
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.wazuh_sources import WazuhSources
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.agent_deployment import AgentDeployment
from wazuh_testing.qa_ctl.provisioning.wazuh_deployment.manager_deployment import ManagerDeployment
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_runner import AnsibleRunner
from wazuh_testing.qa_ctl.provisioning.ansible.ansible_task import AnsibleTask
from wazuh_testing.qa_ctl.provisioning.qa_framework.qa_framework import QAFramework
from wazuh_testing.tools.thread_executor import ThreadExecutor
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging


class QAProvisioning():
    """Class to control different options and instances to provisioning with Wazuh and QA Framework.

    Args:
        provision_info (dict): Dict with all the info needed coming from config file.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.

    Attributes:
        provision_info (dict): Dict with all the info needed coming from config file.
        instances_list (list): List with every instance (each host) needed to build the ansible inventory.
        group_dict (dict): Dict with groups and every host belonging to them.
        host_list (list): List with every host given in config file.
        inventory_file_path (string): Path of the inventory file generated.
        wazuh_installation_paths (dict): Dict indicating the Wazuh installation paths for every host.
        qa_ctl_configuration (QACTLConfiguration): QACTL configuration.
    """

    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, provision_info, qa_ctl_configuration):
        self.provision_info = provision_info
        self.instances_list = []
        self.group_dict = {}
        self.host_list = []
        self.inventory_file_path = None
        self.wazuh_installation_paths = {}
        self.qa_ctl_configuration = qa_ctl_configuration

        self.__process_inventory_data()

    def __read_ansible_instance(self, host_info):
        """Read every host info and generate the AnsibleInstance object.

        Args:
            host_info (dict): Dict with the host info needed coming from config file.

        Returns:
            instance (AnsibleInstance): Contains the AnsibleInstance for a given host.
        """
        extra_vars = None if 'host_vars' not in host_info else host_info['host_vars']
        private_key_path = None if 'local_private_key_file_path' not in host_info \
                                   else host_info['local_private_key_file_path']
        instance = AnsibleInstance(host=host_info['host'], host_vars=extra_vars,
                                   connection_method=host_info['connection_method'],
                                   connection_port=host_info['connection_port'], connection_user=host_info['user'],
                                   connection_user_password=host_info['password'],
                                   ssh_private_key_file_path=private_key_path,
                                   ansible_python_interpreter=host_info['ansible_python_interpreter'])
        return instance

    def __process_inventory_data(self):
        """Process config file info to generate the ansible inventory file."""
        QAProvisioning.LOGGER.debug('Processing inventory data from provisioning hosts info')

        for root_key, root_value in self.provision_info.items():
            if root_key == "hosts":
                for _, host_value in root_value.items():
                    for module_key, module_value in host_value.items():
                        if module_key == "host_info":
                            current_host = module_value['host']
                            if current_host:
                                self.instances_list.append(self.__read_ansible_instance(module_value))
            elif root_key == "groups":
                self.group_dict.update(self.provision_info[root_key])

        inventory_instance = AnsibleInventory(ansible_instances=self.instances_list,
                                              ansible_groups=self.group_dict)
        self.inventory_file_path = inventory_instance.inventory_file_path
        QAProvisioning.LOGGER.debug('The inventory data from provisioning hosts info has been processed successfully')

    def __process_config_data(self, host_provision_info):
        """Process config file info to generate all the tasks needed for deploy Wazuh

        Args:
            host_provision_info (dict): Dicionary with host provisioning info
        """
        current_host = host_provision_info['host_info']['host']

        if 'wazuh_deployment' in host_provision_info:
            deploy_info = host_provision_info['wazuh_deployment']
            health_check = True if 'health_check' not in host_provision_info['wazuh_deployment'] \
                else host_provision_info['wazuh_deployment']['health_check']
            install_target = None if 'target' not in deploy_info else deploy_info['target']
            install_type = None if 'type' not in deploy_info else deploy_info['type']
            installation_files_path = None if 'installation_files_path' not in deploy_info \
                else deploy_info['installation_files_path']
            wazuh_install_path = None if 'wazuh_install_path' not in deploy_info \
                else deploy_info['wazuh_install_path']
            wazuh_branch = 'master' if 'wazuh_branch' not in deploy_info else deploy_info['wazuh_branch']
            s3_package_url = None if 's3_package_url' not in deploy_info \
                else deploy_info['s3_package_url']
            system = None if 'version' not in deploy_info \
                else deploy_info['system']
            version = None if 'version' not in deploy_info \
                else deploy_info['version']
            repository = None if 'repository' not in deploy_info \
                else deploy_info['repository']
            revision = None if 'revision' not in deploy_info \
                else deploy_info['revision']
            local_package_path = None if 'local_package_path' not in deploy_info \
                else deploy_info['local_package_path']
            manager_ip = None if 'manager_ip' not in deploy_info else deploy_info['manager_ip']

            installation_files_parameters = {'wazuh_target': install_target}

            if installation_files_path:
                installation_files_parameters['installation_files_path'] = installation_files_path
            if wazuh_install_path:
                installation_files_parameters['wazuh_install_path'] = wazuh_install_path

            installation_files_parameters['qa_ctl_configuration'] = self.qa_ctl_configuration

            if install_type == 'sources':
                installation_files_parameters['wazuh_branch'] = wazuh_branch
                installation_instance = WazuhSources(**installation_files_parameters)
            if install_type == 'package':

                if s3_package_url is None and local_package_path is None:
                    installation_files_parameters['system'] = system
                    installation_files_parameters['version'] = version
                    installation_files_parameters['revision'] = revision
                    installation_files_parameters['repository'] = repository
                    installation_instance = WazuhS3Package(**installation_files_parameters)
                    remote_files_path = installation_instance.download_installation_files(self.inventory_file_path,
                                                                                          hosts=current_host)
                elif s3_package_url is None and local_package_path is not None:
                    installation_files_parameters['local_package_path'] = local_package_path
                    installation_instance = WazuhLocalPackage(**installation_files_parameters)
                    remote_files_path = installation_instance.download_installation_files(self.inventory_file_path,
                                                                                          hosts=current_host)
                else:
                    installation_files_parameters['s3_package_url'] = s3_package_url
                    installation_instance = WazuhS3Package(**installation_files_parameters)
                    remote_files_path = installation_instance.download_installation_files(self.inventory_file_path,
                                                                                          hosts=current_host)
            if install_target == 'agent':
                deployment_instance = AgentDeployment(remote_files_path,
                                                      inventory_file_path=self.inventory_file_path,
                                                      install_mode=install_type, hosts=current_host,
                                                      server_ip=manager_ip,
                                                      qa_ctl_configuration=self.qa_ctl_configuration)
            if install_target == 'manager':
                deployment_instance = ManagerDeployment(remote_files_path,
                                                        inventory_file_path=self.inventory_file_path,
                                                        install_mode=install_type, hosts=current_host,
                                                        qa_ctl_configuration=self.qa_ctl_configuration)
            deployment_instance.install()

            if health_check:
                # Wait for Wazuh initialization before health_check
                health_check_sleep_time = 60
                QAProvisioning.LOGGER.info(f"Waiting {health_check_sleep_time} seconds before performing the "
                                           f"healthcheck in {current_host} host")
                sleep(health_check_sleep_time)
                deployment_instance.health_check()

            self.wazuh_installation_paths[deployment_instance.hosts] = deployment_instance.install_dir_path

        if 'qa_framework' in host_provision_info:
            qa_framework_info = host_provision_info['qa_framework']
            wazuh_qa_branch = None if 'wazuh_qa_branch' not in qa_framework_info \
                else qa_framework_info['wazuh_qa_branch']

            qa_instance = QAFramework(qa_branch=wazuh_qa_branch,
                                      ansible_output=self.qa_ctl_configuration.ansible_output)
            qa_instance.download_qa_repository(inventory_file_path=self.inventory_file_path, hosts=current_host)
            qa_instance.install_dependencies(inventory_file_path=self.inventory_file_path, hosts=current_host)
            qa_instance.install_framework(inventory_file_path=self.inventory_file_path, hosts=current_host)

    def __check_hosts_connection(self, hosts='all'):
        """Check that all hosts are reachable via SSH connection

        Args:
            hosts (str): Hosts to check.
        """
        QAProvisioning.LOGGER.info('Checking hosts SSH connection')
        wait_for_connection = AnsibleTask({'name': 'Waiting for SSH hosts connection are reachable',
                                           'wait_for_connection': {'delay': 5, 'timeout': 60}})

        playbook_parameters = {'hosts': hosts, 'tasks_list': [wait_for_connection]}

        AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters,
                                          output=self.qa_ctl_configuration.ansible_output)
        QAProvisioning.LOGGER.info('Hosts connection OK. The instances are accessible via ssh')

    def run(self):
        """Provision all hosts in a parallel way"""
        self.__check_hosts_connection()
        provision_threads = [ThreadExecutor(self.__process_config_data, parameters={'host_provision_info': host_value})
                             for _, host_value in self.provision_info['hosts'].items()]
        QAProvisioning.LOGGER.info(f"Provisioning {len(provision_threads)} instances")

        for runner_thread in provision_threads:
            runner_thread.start()

        for runner_thread in provision_threads:
            runner_thread.join()

        QAProvisioning.LOGGER.info(f"The instances have been provisioned sucessfully")

    def destroy(self):
        """Destroy all the temporary files created by an instance of this object"""
        if os.path.exists(self.inventory_file_path):
            os.remove(self.inventory_file_path)
