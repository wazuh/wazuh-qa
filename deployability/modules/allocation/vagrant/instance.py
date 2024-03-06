import re
import subprocess
import boto3

from pathlib import Path

from modules.allocation.generic import Instance
from modules.allocation.generic.models import ConnectionInfo
from modules.allocation.generic.utils import logger
from .credentials import VagrantCredentials
from .utils import VagrantUtils


class VagrantInstance(Instance):
    """
    The VagrantInstance class represents a Vagrant virtual machine instance.
    It inherits from the generic Instance class.

    Attributes:
        path (str or Path): Directory where instance data is stored.
        identifier (str): Identifier of the instance.
        credentials (VagrantCredentials): Vagrant credentials object.
        host_identifier (str, optional): The host for the instance. Defaults to None.
        host_instance_dir (str | Path, optional): The remote directory of the instance. Defaults to None.
        ssh_port (str): SSH port of the instance.
        macos_host_parameters (dict): Parameters of the remote host.
    """
    def __init__(self, path: str | Path, identifier: str, platform: str, credentials: VagrantCredentials = None, host_identifier: str = None, host_instance_dir: str | Path = None, macos_host_parameters: dict = None, arch: str = None, ssh_port: str = None, user: str = None) -> None:
        """
        Initializes a VagrantInstance.

        Args:
            path (str | Path): The path of the instance.
            identifier (str): The identifier of the instance.
            platform (str): The platform of the instance.
            credentials (VagrantCredentials, optional): The credentials of the instance. Defaults to None.
            host_identifier (str, optional): The host for the instance. Defaults to None.
            host_instance_dir (str | Path, optional): The remote directory of the instance. Defaults to None.
            macos_host_parameters (dict, optional): The parameters of the remote host. Defaults to None.
            arch (str, optional): The architecture of the instance. Defaults to None.
            ssh_port (str, optional): The SSH port of the instance. Defaults to None.
            user (str): User associated with the instance.
        """
        super().__init__(path, identifier, platform, credentials, host_identifier, host_instance_dir, macos_host_parameters, arch, ssh_port, user)
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
        if str(self.host_identifier) == "macstadium":
            logger.debug(f"Deleting remote directory {self.host_instance_dir}")
            VagrantUtils.remote_command(f"sudo rm -rf {self.host_instance_dir}", self.macos_host_parameters)
            logger.debug(f"Killing remote process on port {self.ssh_port}")
            proccess = VagrantUtils.remote_command(f"sudo lsof -Pi :{self.ssh_port} -sTCP:LISTEN -t", self.macos_host_parameters)
            VagrantUtils.remote_command(f"sudo kill -9 {proccess}", self.macos_host_parameters)
        if str(self.host_identifier) == "black_mini":
            logger.debug(f"Deleting remote directory {self.host_instance_dir}")
            VagrantUtils.remote_command(f"sudo rm -rf {self.host_instance_dir}", self.macos_host_parameters)


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
        if self.platform == 'macos':
            for key, pattern in patterns.items():
                match = re.search(pattern, output)
                if match and key == 'hostname':
                    ip = match.group(1).strip()
            server_ip = self.macos_host_parameters['server_ip']
            tmp_port_file = str(self.path) + "/port.txt"
            if str(self.host_identifier) == "macstadium":
                if not Path(tmp_port_file).exists():
                    port = VagrantUtils.get_port(self.macos_host_parameters)
                    cmd = f"sudo /usr/bin/ssh -i /Users/jenkins/.ssh/localhost -L {server_ip}:{port}:{ip}:22 -N 127.0.0.1 -f"
                    VagrantUtils.remote_command(cmd, self.macos_host_parameters)
                    with open(tmp_port_file, 'w') as f:
                        f.write(port)
                else:
                    with open(tmp_port_file, 'r') as f:
                        port = f.read()
                ssh_config['port'] = port
            else:
                with open(tmp_port_file, 'r') as f:
                    port = f.read()
                ssh_config['port'] = port
            ssh_config['hostname'] = server_ip
            ssh_config['user'] = 'vagrant'
            ssh_config['password'] = 'vagrant'
        elif self.platform == 'windows':
            for key, pattern in patterns.items():
                match = re.search(pattern, output)
                if match and key == 'hostname':
                    ip = match.group(1).strip()
            ssh_config['hostname'] = ip
            ssh_config['port'] = 3389
            ssh_config['user'] = 'vagrant'
            ssh_config['password'] = 'vagrant'
        else:
            for key, pattern in patterns.items():
                match = re.search(pattern, output)
                if match:
                    ssh_config[key] = str(match.group(1)).strip("\r")
                else:
                    logger.error(f"Couldn't find {key} in ssh-config")
                    return None
            if self.credentials:
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
        if isinstance(command, str):
            command = [command]
        if self.platform == 'macos':
            cmd = f"sudo VAGRANT_CWD={self.host_instance_dir} /usr/local/bin/vagrant " + ' '.join(command)
            output = VagrantUtils.remote_command(cmd, self.macos_host_parameters)
            return output
        else:
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
