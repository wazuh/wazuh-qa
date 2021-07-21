from wazuh_testing.provisioning.wazuh_deployment.ManagerDeployment import ManagerDeployment
from wazuh_testing.provisioning.wazuh_deployment.AgentDeployment import AgentDeployment


# my_wazuh_server_deployment = ManagerDeployment('/home/vagrant/wazuh', install_mode='sources', install_dir_path='/var/ossec', hosts='server')
# if not my_wazuh_server_deployment.wazuh_is_already_installed():
#     my_wazuh_server_deployment.install()
# my_wazuh_server_deployment.start_service()
# my_wazuh_server_deployment.health_check()

# my_wazuh_agent_deployment = AgentDeployment('/home/vagrant/wazuh', install_mode='sources', install_dir_path='/var/ossec', ip_server='10.2.0.13', hosts='agent')
# if not my_wazuh_agent_deployment.wazuh_is_already_installed():
#     my_wazuh_agent_deployment.install()
# my_wazuh_agent_deployment.register_agent()

my_wazuh_agent_deployment2 = AgentDeployment('c:\\program files (x86)\\', install_mode='sources', install_dir_path='c:\\program files (x86)\\ossec-agent', server_ip='10.2.0.13', hosts='agent')
install_output = my_wazuh_agent_deployment2.install()
print(install_output)
print(install_output.stdout)
print(install_output.stderr)
my_wazuh_agent_deployment2.register_agent()
