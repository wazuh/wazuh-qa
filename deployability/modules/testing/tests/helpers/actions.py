import time
import subprocess
import os
import platform

from . import utils


class WazuhInstaller:
    def __init__(self, os_type, wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, type_os=None, architecture=None):
        self.os_type = os_type
        self.wazuh_version = wazuh_version
        self.wazuh_revision = wazuh_revision
        self.aws_s3 = aws_s3
        self.repository = repository
        self.dependency_ip = dependency_ip
        self.type_os = type_os
        self.architecture = architecture

    def install_agent(self):
        if self.os_type == 'linux':
            self._install_linux_agent()
        elif self.os_type == 'windows':
            self._install_windows_agent()
        elif self.os_type == 'macos':
            self._install_macos_agent()
        else:
            print("Unsupported operating system.")

    def _install_linux_agent(self):
        base_url = f"https://{self.aws_s3}/{self.repository}/yum/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}"

        architecture_suffix = {'x86_64': 'amd64', 'aarch64': 'aarch64'}

        url = f"{base_url}.{architecture_suffix.get(self.architecture)}.rpm"
        download_command = f'wget {url} -O wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}.{self.architecture}.rpm'
        install_command = f"sudo WAZUH_MANAGER='{self.dependency_ip}' rpm -ihv wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.{self.architecture}.rpm"

        if self.type_os == 'deb':
            architecture_suffix['x86_64'] = 'amd64'
            url = f"https://{self.aws_s3}.wazuh.com/{self.repository}/apt/pool/main/w/wazuh-agent/wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}_{architecture_suffix.get(self.architecture)}.deb"
            download_command = f'wget {url} -O wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}_{self.architecture}.deb'
            install_command = f"sudo WAZUH_MANAGER='{self.dependency_ip}' dpkg -i ./wazuh-agent_{self.wazuh_version}-{self.wazuh_revision}_{self.architecture}.deb"

        try:
            subprocess.run(download_command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")

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
        install_command = f"Invoke-WebRequest -Uri {self.aws_s3}/{self.repository}/windows/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='{self.dependency_ip}' WAZUH_REGISTRATION_SERVER='{self.dependency_ip}'"

        utils.run_command(install_command)

        post_install_command = "NET START WazuhSvc"
        utils.run_command(post_install_command)

    def _install_macos_agent(self):
        if self.architecture == 'Intel':
            command = f"curl -so wazuh-agent.pkg {self.aws_s3}/{self.repository}/macos/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.intel64.pkg && echo 'WAZUH_MANAGER='{self.dependency_ip}'' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"
        elif self.architecture == 'Apple':
            command = f"curl -so wazuh-agent.pkg {self.aws_s3}/{self.repository}/macos/wazuh-agent-{self.wazuh_version}-{self.wazuh_revision}.arm64.pkg && echo 'WAZUH_MANAGER='{self.dependency_ip}'' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"

        utils.run_command(command)

        post_install_command = "sudo /Library/Ossec/bin/wazuh-control start"
        utils.run_command(post_install_command)

class WazuhUninstaller:
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
                print(f"Error al ejecutar el comando: {e}")

        post_uninstall_commands = [
            "systemctl disable wazuh-agent",
            "systemctl daemon-reload"
        ]

        for command in post_uninstall_commands:
            try:
                subprocess.run(command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar el comando: {e}")

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

class CheckFile:
    def __init__(self):
        self.initial_scan = None
        self.second_scan = None

    def perform_action_and_scan(self, callback):
        """
        Frame where check-file is taken before and after the callback

        Args:
            callback (callback): callback that can modify the file directory

        Returns:
            dict: added and removed files
        """
        host_info = HostInfo()
        self.initial_scan = self._checkfiles(host_info.get_os_type())

        callback()

        self.second_scan = self._checkfiles(host_info.get_os_type())

        removed = list(set(self.initial_scan) - set(self.second_scan))
        added = list(set(self.second_scan) - set(self.initial_scan))
        changes = {
                'added': added,
                'removed': removed
                }

        return changes

    def get_changes(self):
        if self.initial_scan is None or self.second_scan is None:
            print("Error: Scans not performed.")
            return None

        removed = list(set(self.initial_scan) - set(self.second_scan))
        added = list(set(self.second_scan) - set(self.initial_scan))
        changes = {
                'added': added,
                'removed': removed
                }

        return changes

    def _checkfiles(self, os_type):
        """
        It captures a structure of a /Var or c: directory status

        Returns:
            List: list of directories
        """
        if os_type == 'linux' or os_type == 'macos':
            command = "sudo find /var -type f -o -type d 2>/dev/null"
        elif os_type == 'windows':
            command = 'dir /a-d /b /s | findstr /v /c:"\\.$" /c:"\\..$"| find /c ":"'
        else:
            print("Unsupported operating system.")
            return None

        result = subprocess.run(command, shell=True, executable="/bin/bash", stdout=subprocess.PIPE, text=True)

        if result.returncode == 0:
            paths = [path.strip() for path in result.stdout.split('\n') if path.strip()]
            return paths
        else:
            print(f"Error executing command. Return code: {result.returncode}")
            return None
        
        
class HostInfo:
    def __init__(self):
        pass

    def get_os_type(self):
        """
        It returns the os_type of host

        Returns:
            str: type of host (windows, linux, macos)
        """
        system = platform.system()

        if system == 'Windows':
            return 'windows'
        elif system == 'Linux':
            return 'linux'
        elif system == 'Darwin':
            return 'macos'
        else:
            return 'unknown'

    def get_architecture(self):
        """
        It returns the arch of host

        Returns:
            str: arch (aarch64, x86_64, intel, apple)
        """
        return platform.machine()

    def get_linux_distribution(self):
        """
        It returns the linux distribution of host

        Returns:
            str: linux distribution (deb, rpm)
        """
        if self.get_os_type() == 'linux':
            package_managers = {
                '/etc/debian_version': 'deb',
                '/etc/redhat-release': 'rpm',
            }

            for file_path, package_manager in package_managers.items():
                if os.path.exists(file_path):
                    return package_manager