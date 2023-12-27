import re
import subprocess

from pathlib import Path

from .generic import ConnectionInfo, Instance


class VagrantInstance(Instance):
    def __init__(self, base_dir: str | Path, name: str, identifier: str, key_pair: str | Path) -> None:
        super().__init__(base_dir, name, identifier, key_pair)
            
        self.vagrantfile_path: Path = Path(self.path, 'Vagrantfile')

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
        self.__run_vagrant_command('destroy -f')

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

        ssh_config['private_key'] = self.key_pair
        return ConnectionInfo(**ssh_config)

    def __run_vagrant_command(self, command: str) -> str:
        """
        Runs a Vagrant command and returns its output.

        Args:
            command (str): The vagrant command to run.

        Returns:
            str: The output of the command.
        """
        try:
            output = subprocess.run(["vagrant", command, self.name],
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
                status = status_line.split()[1]
                return status
