import re
import subprocess

from pathlib import Path

from modules.allocation.generic import Instance
from modules.allocation.generic.models import ConnectionInfo
from modules.allocation.generic.utils import logger
from .credentials import VagrantCredentials


class VagrantInstance(Instance):
    """
    The VagrantInstance class represents a Vagrant virtual machine instance.
    It inherits from the generic Instance class.

    Attributes:
        path (str or Path): Directory where instance data is stored.
        identifier (str): Identifier of the instance.
        credentials (VagrantCredentials): Vagrant credentials object.
    """
    def __init__(self, path: str | Path, identifier: str, credentials: VagrantCredentials = None) -> None:
        """
        Initializes a VagrantInstance.

        Args:
            path (str | Path): The path of the instance.
            identifier (str): The identifier of the instance.
            credentials (VagrantCredentials, optional): The credentials of the instance. Defaults to None.
        """
        super().__init__(path, identifier, credentials)
        self.vagrantfile_path: Path = self.path / 'Vagrantfile'

    def start(self) -> None:
        """
        Starts the Vagrant virtual machine.

        Returns:
            None
        """
        self.__run_vagrant_command('up')

    def reload(self) -> None:
        """
        Reloads the Vagrant virtual machine.

        Returns:
            None
        """
        self.__run_vagrant_command('reload')

    def stop(self) -> None:
        """
        Stops the Vagrant virtual machine.

        Returns:
            None
        """
        self.__run_vagrant_command('halt')

    def delete(self) -> None:
        """
        Deletes the Vagrant virtual machine.

        Returns:
            None
        """
        if "not created" in self.status():
            logger.warning(f"Instance {self.identifier} is not created.\
                            Skipping deletion.")
            return
        self.__run_vagrant_command(['destroy', '-f'])

    def status(self) -> str:
        """
        Checks the status of the Vagrant virtual machine.

        Returns:
            str: The status of the instance.
        """
        output = self.__run_vagrant_command('status')
        return self.__parse_vagrant_status(output)

    def ssh_connection_info(self) -> ConnectionInfo:
        """
        Returns the SSH configuration of the Vagrant virtual machine.

        Returns:
            ConnectionInfo: The SSH configuration of the VM.
        """
        if not 'running' in self.status():
            logger.debug(f"Instance {self.identifier} is not running.\
                            Starting it.")
            self.start()
        output = self.__run_vagrant_command('ssh-config')
        patterns = {'hostname': r'HostName (.*)',
                    'user': r'User (.*)',
                    'port': r'Port (.*)',
                    'private_key': r'IdentityFile (.*)'}
        # Parse the ssh-config.
        ssh_config = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                ssh_config[key] = str(match.group(1)).strip("\r")
            else:
                logger.error(f"Couldn't find {key} in ssh-config")
                return None
        if self.credentials:
            logger.debug(f"Using provided credentials")
            ssh_config['private_key'] = str(self.credentials.key_path)
        return ConnectionInfo(**ssh_config)

    def __run_vagrant_command(self, command: str | list) -> str:
        """
        Runs a Vagrant command and returns its output.

        Args:
            command (str | list): The Vagrant command to run.

        Returns:
            str: The output of the command.
        """
        if not isinstance(command, list):
            command = [command]
        try:
            output = subprocess.run(["vagrant", *command],
                                    cwd=self.path,
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            if stderr := output.stderr.decode("utf-8"):
                logger.error(f"Command failed: {stderr}")
                return None
            return output.stdout.decode("utf-8")
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr}")
            return None

    def __parse_vagrant_status(self, message: str) -> str:
        """
        Parses the status of the Vagrant virtual machine.

        Args:
            message (str): The message to parse.

        Returns:
            str: The parsed status.
        """
        lines = message.split('\n')
        for line in lines:
            if 'Current machine states:' in line:
                status_line = lines[lines.index(line) + 2]
                status = ' '.join(status_line.split()[1:])
                status = status.split('(')[0].strip()
                return status
