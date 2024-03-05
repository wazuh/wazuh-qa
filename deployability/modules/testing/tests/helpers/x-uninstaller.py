
import subprocess
from . import utils


class WazuhAgentUninstaller:
    def __init__(self, os_type, wazuh_version, wazuh_revision, type_os=None):
        self.os_type = os_type
        self.wazuh_version = wazuh_version
        self.wazuh_revision = wazuh_revision
        self.type_os = type_os

    def uninstall_agent(self):
        if self.os_type == 'linux':
            self._uninstall_linux_agent()
        elif self.os_type == 'windows':
            self._uninstall_windows_agent()
        elif self.os_type == 'macos':
            self._uninstall_macos_agent()
        else:
            print("Unsupported operating system.")

    def _uninstall_linux_agent(self):
        if self.type_os == 'rpm':
            uninstall_commands = ["yum remove wazuh-agent"]
        elif self.type_os == 'deb':
            uninstall_commands = [
            "sudo apt-get remove -y wazuh-agent",
            "sudo apt-get remove -y --purge wazuh-agent"
            ]

        for command in uninstall_commands:
            try:
                subprocess.run(command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error executing the command: {e}")

        post_uninstall_commands = [
            "systemctl disable wazuh-agent",
            "systemctl daemon-reload"
        ]

        for command in post_uninstall_commands:
            try:
                subprocess.run(command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error executing the command: {e}")

    def _uninstall_windows_agent(self):
        uninstall_command = f"msiexec.exe /x wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.msi /qn"

        utils.run_command(uninstall_command)

    def _uninstall_macos_agent():
        uninstall_commands = [
            "/Library/Ossec/bin/wazuh-control stop",
            "/bin/rm -r /Library/Ossec",
            "/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist",
            "/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist",
            "/bin/rm -rf /Library/StartupItems/WAZUH",
            "/usr/bin/dscl . -delete \"/Users/wazuh\"",
            "/usr/bin/dscl . -delete \"/Groups/wazuh\"",
            "/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent"
        ]

        for command in uninstall_commands:
            utils.run_command(command)


import subprocess
from . import utils


class WazuhAgentUninstaller:
    def __init__(self, os_type, wazuh_version, wazuh_revision, type_os=None):
        self.os_type = os_type
        self.wazuh_version = wazuh_version
        self.wazuh_revision = wazuh_revision
        self.type_os = type_os

    def uninstall_agent(self):
        if self.os_type == 'linux':
            self._uninstall_linux_agent()
        elif self.os_type == 'windows':
            self._uninstall_windows_agent()
        elif self.os_type == 'macos':
            self._uninstall_macos_agent()
        else:
            print("Unsupported operating system.")

    def _uninstall_linux_agent(self):
        if self.type_os == 'rpm':
            uninstall_commands = ["yum remove wazuh-agent"]
        elif self.type_os == 'deb':
            uninstall_commands = [
            "sudo apt-get remove -y wazuh-agent",
            "sudo apt-get remove -y --purge wazuh-agent"
            ]

        for command in uninstall_commands:
            try:
                subprocess.run(command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error executing the command: {e}")

        post_uninstall_commands = [
            "systemctl disable wazuh-agent",
            "systemctl daemon-reload"
        ]

        for command in post_uninstall_commands:
            try:
                subprocess.run(command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error executing the command: {e}")

    def _uninstall_windows_agent(self):
        uninstall_command = f"msiexec.exe /x wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.msi /qn"

        utils.run_command(uninstall_command)

    def _uninstall_macos_agent():
        uninstall_commands = [
            "/Library/Ossec/bin/wazuh-control stop",
            "/bin/rm -r /Library/Ossec",
            "/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist",
            "/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist",
            "/bin/rm -rf /Library/StartupItems/WAZUH",
            "/usr/bin/dscl . -delete \"/Users/wazuh\"",
            "/usr/bin/dscl . -delete \"/Groups/wazuh\"",
            "/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent"
        ]

        for command in uninstall_commands:
            utils.run_command(command)


class WazuhManagerUninstaller:
    def __init__(self, linux_distribution, component, wazuh_version, aws_s3):
        self.linux_distribution = linux_distribution
        self.component = component
        self.wazuh_version = wazuh_version
        self.aws_s3 = aws_s3

    def uninstall_central_components(self):
        package_name = f"wazuh-{self.component}"
        command = ""

        case_dict = {
            'all': lambda: f"curl -sO https://{self.aws_s3}.wazuh.com/{self.wazuh_version}/wazuh-install.sh && sudo bash wazuh-install.sh --uninstall",
            'dashboard': lambda: f"apt-get remove --purge {package_name} -y" if self.linux_distribution == 'deb' else f"yum remove {package_name} -y && rm -rf /var/lib/{package_name}/ && rm -rf /usr/share/{package_name}/ && rm -rf /etc/{package_name}/",
            'server': lambda: self._uninstall_server(),
            'filebeat': lambda: self._uninstall_filebeat(),
            'indexer': lambda: f"apt-get remove --purge {package_name} -y" if self.linux_distribution == 'deb' else f"yum remove {package_name} -y && rm -rf /var/lib/{package_name}/ && rm -rf /usr/share/{package_name}/ && rm -rf /etc/{package_name}/",
        }

        if self.component == 'server':
            command = f"{self._uninstall_server()} && {self._disable_server()} && {self._uninstall_filebeat()}"
        else:
            command = case_dict.get(self.component, lambda: "")()
        print(command)
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing the command: {e}")

    def _uninstall_server(self):
        package_name = "wazuh-server"
        return f"apt-get remove --purge {package_name} -y" if self.linux_distribution == 'deb' else f"yum remove {package_name} -y && rm -rf /var/ossec/"

    def _disable_server(self):
        return "systemctl disable wazuh-manager && systemctl daemon-reload"

    def _uninstall_filebeat(self):
        package_name = "wazuh-filebeat"
        return f"apt-get remove --purge {package_name} -y" if self.linux_distribution == 'deb' else f"yum remove {package_name} -y && rm -rf /var/lib/{package_name}/ && rm -rf /usr/share/{package_name}/ && rm -rf /etc/{package_name}/"
