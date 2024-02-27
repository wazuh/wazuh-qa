import subprocess
from . import utils


class WazuhAgentInstaller:
    def __init__(self, os_type, wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, one_line, type_os=None, architecture=None):
        self.os_type = os_type
        self.wazuh_version = wazuh_version
        self.wazuh_revision = wazuh_revision
        self.aws_s3 = aws_s3
        self.repository = repository
        self.dependency_ip = dependency_ip
        self.one_line = one_line
        self.type_os = type_os
        self.architecture = architecture

    def _connection_dependency_ip(self):
        return'MANAGER_IP' if not self.one_line else self.dependency_ip

    def install_agent(self):
        case_dict = {
            'linux': self._install_linux_agent,
            'windows': self._install_windows_agent,
            'macos': self._install_macos_agent
        }

        installation_function = case_dict.get(self.os_type, None)

        if installation_function:
            installation_function()
        else:
            print("Unsupported operating system.")


    def _install_linux_agent(self):
        base_url = f"https://{self.aws_s3}/{self.repository}/yum/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}"

        architecture_suffix = {'x86_64': 'amd64', 'aarch64': 'aarch64'}

        url = f"{base_url}.{architecture_suffix.get(self.architecture)}.rpm"
        download_command = f'wget {url} -O wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}.{self.architecture}.rpm'
        install_command = f"sudo WAZUH_MANAGER='{self._connection_dependency_ip()}' WAZUH_AGENT_NAME='agent-{self.os_type}-{self.dependency_ip}' rpm -ihv wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.{self.architecture}.rpm"

        if self.type_os == 'deb':
            architecture_suffix['x86_64'] = 'amd64'
            url = f"https://{self.aws_s3}.wazuh.com/{self.repository}/apt/pool/main/w/wazuh-agent/wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}_{architecture_suffix.get(self.architecture)}.deb"
            download_command = f'wget {url} -O wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}_{self.architecture}.deb'
            install_command = f"sudo WAZUH_MANAGER='{self._connection_dependency_ip()}' WAZUH_AGENT_NAME='agent-{self.os_type}-{self.dependency_ip}' dpkg -i ./wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}_{self.architecture}.deb"

        try:
            subprocess.run(download_command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing the command: {e}")

        try:
            subprocess.run(install_command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing the command: {e}")

        post_install_commands = [
            "sudo systemctl daemon-reload",
            "sudo systemctl enable wazuh-agent",
            "sudo systemctl start wazuh-agent"
        ]

        for command in post_install_commands:
            try:
                subprocess.run(command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error executing the command: {e}")

    def _install_windows_agent(self):
        install_command = f"Invoke-WebRequest -Uri {self.aws_s3}/{self.repository}/windows/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='{self._connection_dependency_ip()}' WAZUH_AGENT_NAME='agent-{self.os_type}-{self.dependency_ip}' WAZUH_REGISTRATION_SERVER='{self._connection_dependency_ip()}'"

        utils.run_command(install_command)

        post_install_command = "NET START WazuhSvc"
        utils.run_command(post_install_command)

    def _install_macos_agent(self):
        if self.architecture == 'Intel':
            command = f"curl -so wazuh-agent.pkg {self.aws_s3}/{self.repository}/macos/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.intel64.pkg && echo 'WAZUH_MANAGER='{self._connection_dependency_ip()}' && WAZUH_AGENT_NAME='agent-{self.os_type}-{self.dependency_ip}' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"
        elif self.architecture == 'Apple':
            command = f"curl -so wazuh-agent.pkg {self.aws_s3}/{self.repository}/macos/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.arm64.pkg && echo 'WAZUH_MANAGER='{self._connection_dependency_ip()}' && WAZUH_AGENT_NAME='agent-{self.os_type}-{self.dependency_ip}' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"

        utils.run_command(command)

        post_install_command = "sudo /Library/Ossec/bin/wazuh-control start"
        utils.run_command(post_install_command)


class WazuhManagerInstaller:
    def __init__(self, wazuh_version, aws_s3):
        self.wazuh_version = wazuh_version
        self.aws_s3 = aws_s3

    def install_manager(self):
        command = f"curl -sO https://{self.aws_s3}.wazuh.com/{self.wazuh_version}/wazuh-install.sh && sudo bash ./wazuh-install.sh -a"
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing the command: {e}")