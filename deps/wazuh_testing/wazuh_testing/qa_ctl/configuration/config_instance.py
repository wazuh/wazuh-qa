
import json

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


class ConfigInstance:
    """Represent a basic instance to be added later in the qa-ctl configuration file.

    Args:
        name (str): Name assigned to the VM.
        os_system (str): Operating system assigned to the VM. (e.g centos_8)
        cpu (int): Number of CPUs assigned to the VM.
        memory (int): Number of RAM bytes assigned to the VM.
        ip (str): Ip address assigned to the VM.
        os_version (str): Operating system version (e.g CentOS 8) (Used to get the vagrant box info)
        os_platform (str): Operating system platform. (e.g linux)

    Attributes:
        name (str): Name assigned to the VM.
        os_system (str): Operating system assigned to the VM. (e.g centos_8)
        cpu (int): Number of CPUs assigned to the VM.
        memory (int): Number of RAM bytes assigned to the VM.
        ip (str): Ip address assigned to the VM.
        os_version (str): Operating system version (e.g CentOS 8) (Used to get the vagrant box info)
        os_platform (str): Operating system platform. (e.g linux)
    """
    LOGGER = Logging.get_logger(QACTL_LOGGER)

    def __init__(self, name, os_system, memory=1024, cpu=1, ip=None, os_version=None, os_platform=None):
        self.name = name
        self.os_system = os_system
        self.memory = memory
        self.cpu = cpu
        self.ip = ip
        self.os_version = os_version if os_version else self._get_os_version()
        self.os_platform = os_platform if os_platform else self._get_os_platform()

    def _get_os_platform(self):
        """Get the operating system platform according to the os_system.

        Returns:
            str: Operating system platform (e.g linux).
        """
        linux_systems = ['centos', 'ubuntu', 'amazon', 'fedora', 'redhat', 'rhel', 'suse', 'arch']
        if any([system for system in linux_systems if system in self.os_system]):
            return 'linux'
        elif 'windows' in self.os_system:
            return 'windows'
        else:
            raise QAValueError(f"Could not detect the os_platform from {self.os_system} system", self.LOGGER.error,
                               QACTL_LOGGER)

    def _get_os_version(self):
        """Get the operating system version according to the os_system.

        Returns:
            str: Operating system version (e.g CentOS 8).
        """
        latest_system_mapping = {
            'centos': 'centos_8',
            'ubuntu': 'ubuntu_focal',
            'windows': 'windows_2019'
        }
        os_system_mapping = {
            'centos_7': 'CentOS 7',
            'centos_8': 'CentOS 8',
            'windows_2019': 'Windows Server 2019',
            'ubuntu_focal': 'Ubuntu Focal'
        }

        system = latest_system_mapping[self.os_system] if \
            any([system for system in latest_system_mapping.keys() if system == self.os_system]) else self.os_system

        if system not in os_system_mapping.keys():
            raise QAValueError(f"Could not map the {system} to get the OS version", self.LOGGER.error,
                               QACTL_LOGGER)
        return os_system_mapping[system]

    def __str__(self):
        """Define how the class object is to be displayed."""
        return f"name: {self.name}\nos: {self.os_system}\nos_version: {self.os_version}\nos_platform: " \
               f"{self.os_platform}\nmemory: {self.memory}\ncpu: {self.cpu}\nip: {self.ip}\n"

    def __repr__(self):
        """Representation of the object of the class in string format"""
        return json.dumps({
            'name': self.name,
            'os_system': self.os_system,
            'os_version': self.os_version,
            'os_platform': self.os_platform,
            'memory': self.memory,
            'cpu': self.cpu,
            'ip': self.ip,
        })
