import subprocess
from ..helpers.hostinformation import HostInformation


class CheckFiles:
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
        host_info = HostInformation()
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

