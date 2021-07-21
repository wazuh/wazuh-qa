from wazuh_testing.provisioning.wazuh_install.ManagerDeployment import ManagerDeployment
from wazuh_testing.provisioning.wazuh_install.AgentDeployment import AgentDeployment


my_wazuh_server_deployment = ManagerDeployment('/home/vagrant/wazuh-manager_4.1.5-1_amd64.deb', 'linux', install_mode='package', install_dir='/var/ossec', hosts='server')
my_wazuh_server_deployment.install()
my_wazuh_server_deployment.start_service()

my_wazuh_agent_deployment = AgentDeployment('/home/vagrant/wazuh-agent_4.1.5-1_amd64.deb', 'linux', install_mode='package', install_dir='/var/ossec', ip_server='10.2.0.13', hosts='agent')
my_wazuh_agent_deployment.install()
my_wazuh_agent_deployment.register_agent()
