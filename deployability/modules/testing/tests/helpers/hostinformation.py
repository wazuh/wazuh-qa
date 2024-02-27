import platform
import os


class HostInformation:
    def __init__(self):
        pass

    def get_os_type(self):
        """
        It returns the os_type of host

        Returns:
            str: type of host (windows, linux, macos)
        """
        system = platform.system()

        case_dict = {
            'Windows': 'windows',
            'Linux': 'linux',
            'Darwin': 'macos'
        }

        return case_dict.get(system, 'unknown')

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
            raise ValueError("Unable to determine Linux distribution")