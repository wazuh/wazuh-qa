from executor import Executor
from generic import HostInformation

def install_agent(inventory_path):
    hostinformation = HostInformation()
    os_type = hostinformation.get_os_type(inventory_path)
    if 'linux' in os_type:
        distribution = hostinformation.get_linux_distribution(inventory_path)
        architecture = hostinformation.get_architecture(inventory_path)

        if 'rpm' in distribution and 'x86_64' in architecture:
            commands = [
                "curl -o wazuh-agent-4.7.0-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.x86_64.rpm && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' rpm -ihv wazuh-agent-4.7.0-1.x86_64.rpm",
                "systemctl daemon-reload",
                "systemctl enable wazuh-agent",
                "systemctl start wazuh-agent",
                "systemctl status wazuh-agent"
            ]
        
        elif 'rpm' in distribution and 'aarch64' in architecture:
            commands = [
                "curl -o wazuh-agent-4.7.0-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.aarch64.rpm && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' rpm -ihv wazuh-agent-4.7.0-1.aarch64.rpm",
                "systemctl daemon-reload",
                "systemctl enable wazuh-agent",
                "systemctl start wazuh-agent",
                "systemctl status wazuh-agent"
            ]
        elif 'deb' in distribution and 'x86_64' in architecture:
            commands = [
                "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb",
                "systemctl daemon-reload",
                "systemctl enable wazuh-agent",
                "systemctl start wazuh-agent",
                "systemctl status wazuh-agent"
            ]
        elif 'deb' in distribution and 'aarch64' in architecture:
            commands = [
                "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_arm64.deb && sudo WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' dpkg -i ./wazuh-agent_4.7.0-1_arm64.deb",
                "systemctl daemon-reload",
                "systemctl enable wazuh-agent",
                "systemctl start wazuh-agent",
                "systemctl status wazuh-agent"
            ]
    elif 'windows' in os_type :
        commands = [
            "Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.57.2' WAZUH_AGENT_NAME='agente' WAZUH_REGISTRATION_SERVER='192.168.57.2'",
            "NET START WazuhSvc",
            "NET STATUS WazuhSvc"
            ]
    elif 'macos' in os_type:
        if 'intel' in architecture:
            commands = [
                'curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.intel64.pkg && echo "WAZUH_MANAGER=\'192.168.57.2\' && WAZUH_AGENT_NAME=\'agente\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /',
                '/Library/Ossec/bin/wazuh-control start',
                '/Library/Ossec/bin/wazuh-control status'
            ]
        elif 'apple' in architecture:
            commands = [
                'curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.arm64.pkg && echo "WAZUH_MANAGER=\'192.168.57.2\' && WAZUH_AGENT_NAME=\'agente\'" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /',
                '/Library/Ossec/bin/wazuh-control start',
                '/Library/Ossec/bin/wazuh-control status'
            ]
    Executor.execute_commands(inventory_path, commands)

def install_agents(inventories_paths=[]):
    for inventory_path in inventories_paths:
        install_agent(inventory_path)





def uninstall_agent(inventory_path):
    hostinformation = HostInformation()
    os_type = hostinformation.get_os_type(inventory_path)

    if 'linux' in os_type:
        distribution = hostinformation.get_linux_distribution(inventory_path)
        if 'rpm' in distribution:
            commands = [
                "yum remove wazuh-agent -y",
                "rm -rf /var/ossec/",
                "systemctl disable wazuh-agent",
                "systemctl daemon-reload"
            ]

        elif 'deb' in distribution:
            commands = [
                "apt-get remove --purge wazuh-agent -y",
                "systemctl disable wazuh-agent",
                "systemctl daemon-reload"
            ]
    elif 'windows' in os_type:
        commands = [
            "msiexec.exe /x wazuh-agent-4.7.3-1.msi /qn"
        ]
    elif 'macos' in os_type:
        commands = [
            "/Library/Ossec/bin/wazuh-control stop",
            "/bin/rm -r /Library/Ossec",
            "/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist",
            "/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist",
            "/bin/rm -rf /Library/StartupItems/WAZUH",
            "/usr/bin/dscl . -delete '/Users/wazuh'",
            "/usr/bin/dscl . -delete '/Groups/wazuh'",
            "/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent"
        ]
    Executor.execute_commands(inventory_path, commands)



def uninstall_agents(inventories_paths=[]):
    for inventory_path in inventories_paths:
        uninstall_agent(inventory_path)

#---------------------------------------------------


inv = ["/tmp/dtt1-poc/manager-linux-ubuntu-18.04-amd64/inventory.yaml", "/tmp/dtt1-poc/manager-linux-redhat-7-amd64/inventory.yaml"]
uninstall_agents(inv)




""" install_agent_aix = [
    "curl -sO -k https://packages-dev.wazuh.com/pre-release/aix/wazuh-agent-4.7.0-1.aix.ppc.rpm ",
    "WAZUH_MANAGER='44.211.192.146' rpm -ivh wazuh-agent-4.7.0-1.aix.ppc.rpm",
    "/var/ossec/bin/wazuh-control start"
]
install_agent_hpux = [
    "/usr/local/bin/curl -sOk https://packages-dev.wazuh.com/pre-release/hp-ux/wazuh-agent-4.7.0-1-hpux-11v3-ia64.tar",
    "groupadd wazuh",
    "useradd -G wazuh wazuh",
    "tar -xvf wazuh-agent-4.7.0-1-hpux-11v3-ia64.tar",
    "sed 's/MANAGER_IP/44.211.192.146/g' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf",
    "/var/ossec/bin/wazuh-control start"
]
install_agent_solaris11 = [
    "curl -o wazuh-agent_v4.7.0-sol11-sparc.p5p https://packages-dev.wazuh.com/pre-release/solaris/sparc/11/wazuh-agent_v4.7.0-sol11-sparc.p5p",
    "pkg install -g wazuh-agent_v4.7.0-sol11-sparc.p5p wazuh-agent",
    "sed 's/MANAGER_IP/44.211.192.146/g' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf"
    "/var/ossec/bin/wazuh-control start"
]
install_agent_solaris10 = [
    "pkgadd -d wazuh-agent_v4.7.0-sol10-sparc.pkg",
    "sed 's/MANAGER_IP/44.211.192.146/g' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf",
    "/var/ossec/bin/wazuh-control start"
]
install_agent_centos_ppc64le = [
    "curl -OL https://packages-dev.wazuh.com/pre-release/yum/wazuh-agent-4.7.0-1.ppc64le.rpm",
    "yum install -y ./wazuh-agent-4.7.0-1.ppc64le.rpm",
    "sed 's/MANAGER_IP/44.211.192.146/g' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf",
    "/var/ossec/bin/wazuh-control start"
]
install_agent_debian_ppc64le = [
    "WAZUH_MANAGER='X.X.X.X' apt-get install ./wazuh-agent_4.7.0-1_ppc64el.deb",
    "/var/ossec/bin/wazuh-control start"
] """