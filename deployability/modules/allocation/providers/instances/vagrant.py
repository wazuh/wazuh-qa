import re
import subprocess

from pathlib import Path

from .generic import ConnectionInfo, Instance
from ..credentials.vagrant import VagrantCredentials

class VagrantInstance(Instance):
    def __init__(self, path: str | Path, identifier: str, credentials: VagrantCredentials) -> None:
        super().__init__(path, identifier, credentials)
            
        self.vagrantfile_path: Path = self.path / 'Vagrantfile'

    def start(self) -> None:
        """Starts the vagrant VM."""
        self.__run_vagrant_command('up')

    def stop(self) -> None:
        """Stops the vagrant VM."""
        self.__run_vagrant_command('halt')

    def delete(self) -> None:
        """Deletes the vagrant VM and cleans the environment."""
        if "not created" in self.status():
            return
        self.__run_vagrant_command(['destroy', '-f'])

    def status(self) -> str:
        """Checks the status of the vagrant VM.

        Returns:
            str: The status of the instance.
        """
        output = self.__run_vagrant_command('status')
        return self.__parse_vagrant_status(output)

    def ssh_connection_info(self) -> ConnectionInfo:
        """Returns the ssh config of the vagrant VM.

        Returns:
            ConnectionInfo: The VM's ssh config.
        """
        if not 'running' in self.status():
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
                ssh_config[key] = match.group(1)
            else:
                raise ValueError(f"Couldn't find {key} in vagrant ssh-config")
        ssh_config['private_key'] = str(self.credentials.key_path)
        return ConnectionInfo(**ssh_config)

    def __run_vagrant_command(self, command: str | list) -> str:
        """
        Runs a Vagrant command and returns its output.

        Args:
            command (str|list): The vagrant command to run.

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
                print(stderr)
                print(output.stdout.decode("utf-8"))
            # logging.warning(f"Command '{command}' completed with errors:\n{stderr}")

            return output.stdout.decode("utf-8")

        except subprocess.CalledProcessError as e:
            print(e)
            # logging.error(f"Command '{command}' failed with error {e.returncode}:\n{e.output.decode('utf-8')}")
            return None

    def __parse_vagrant_status(self, message: str) -> str:
        lines = message.split('\n')
        for line in lines:
            if 'Current machine states:' in line:
                status_line = lines[lines.index(line) + 2]
                status = ' '.join(status_line.split()[1:])
                status = status.split('(')[0].strip()
                return status
