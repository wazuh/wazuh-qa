from pathlib import Path
import re
import subprocess

from .generic import ConnectionInfo, Handler

class VagrantHandler(Handler):
    def __init__(self, working_dir: str | Path, vagrantfile_content: str = None) -> None:
        super().__init__(working_dir)
        self.vagrantfile_path = Path(self.working_dir, 'Vagrantfile')
        self.vagrantfile_defined = False

        if vagrantfile_content:
            # Write the Vagrantfile with the given content.
            self.write_vagrantfile(vagrantfile_content)
            self.vagrantfile_defined = True
        elif self.read_vagrantfile():
            # It will use the already existing Vagrantifile.
            self.vagrantfile_defined = True

    def start(self) -> None:
        """Starts the vagrant VM."""
        if not self.vagrantfile_defined:
            raise Exception('Vagrantfile not defined.')
        self.__run_vagrant_command('up')

    def stop(self) -> None:
        """Stops the vagrant VM."""
        if not self.vagrantfile_defined:
            raise Exception('Vagrantfile not defined.')
        self.__run_vagrant_command('halt')

    def delete(self) -> None:
        """Deletes the vagrant VM and cleans the environment."""
        if not self.vagrantfile_defined:
            raise Exception('Vagrantfile not defined.')
        self.__run_vagrant_command('destroy -f')

    def status(self) -> str:
        """Checks the status of the vagrant VM.

        Returns:
            str: The status of the instance.
        """
        if not self.vagrantfile_defined:
            raise Exception('Vagrantfile not defined.')
        output = self.__run_vagrant_command('status')
        return self.__parse_vagrant_status(output)

    def get_ssh_config(self) -> ConnectionInfo:
        """Returns the ssh config of the vagrant VM.

        Returns:
            ConnectionInfo: The VM's ssh config.
        """
        if not self.vagrantfile_defined:
            raise Exception('Vagrantfile not defined.')
        ssh_config = {}
        output = self.__run_vagrant_command('ssh-config')
        patterns = {'hostname': r'HostName (.*)',
                    'user': r'User (.*)',
                    'port': r'Port (.*)',
                    'private_key': r'IdentityFile (.*)'}
        # Parse the ssh-config.
        for key, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                ssh_config[key] = match.group(1)
            else:
                raise ValueError(f"Couldn't find {key} in vagrant ssh-config")
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
            output = subprocess.run(["vagrant", command],
                                    cwd=self.working_dir,
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

    def write_vagrantfile(self, data: str) -> None:
        """
        Saves a Vagrantfile in the current working_dir.

        Args:
            data (str): The Vagrantfile content to save.

        """
        with open(self.vagrantfile_pat, 'w') as f:
            f.write(data)
        self.vagrantfile_defined = True

    def read_vagrantfile(self) -> str:
        """
        Reads the Vagrantfile in the current working_dir.

        Returns:
            str: The Vagrantfile content.

        """
        if not self.vagrantfile_path.exists():
            return None
        with open(self.vagrantfile_path, 'r') as f:
            return f.read()

    def __parse_vagrant_status(self, message: str) -> str:
        lines = message.split('\n')
        for line in lines:
            if 'Current machine states:' in line:
                status_line = lines[lines.index(line) + 2]
                status = status_line.split()[1]
                return status
