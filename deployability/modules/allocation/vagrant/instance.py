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
        host_identifier (str or Path): Remote directory of the instance.
    """
    def __init__(self, path: str | Path, identifier: str, credentials: VagrantCredentials = None, host_identifier: str | Path = None, ssh_port: str = None) -> None:
        """
        Initializes a VagrantInstance.

        Args:
            path (str | Path): The path of the instance.
            identifier (str): The identifier of the instance.
            credentials (VagrantCredentials, optional): The credentials of the instance. Defaults to None.
            host_identifier (str | Path, optional): The remote directory of the instance. Defaults to None.
            ssh_port (str, optional): The SSH port of the instance. Defaults to None.
        """
        super().__init__(path, identifier, credentials, host_identifier, ssh_port)
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
        if self.host_identifier:
            logger.debug(f"Deleting remote directory {self.host_identifier}")
            VagrantUtils.remote_command(f"sudo rm -rf {self.host_identifier}")
            logger.debug(f"Killing remote process on port {self.ssh_port}")
            proccess = VagrantUtils.remote_command(f"sudo lsof -Pi :{self.ssh_port} -sTCP:LISTEN -t")
            VagrantUtils.remote_command(f"sudo kill -9 {proccess}")


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
        if self.host_identifier:
            for key, pattern in patterns.items():
                match = re.search(pattern, output)
                if match and key == 'hostname':
                    ip = match.group(1).strip()
            client = boto3.client('secretsmanager')
            server_ip = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_ip')['SecretString']
            tmp_port_file = str(self.path) + "/port.txt"
            if not Path(tmp_port_file).exists():
                port = VagrantUtils.get_port()
                cmd = f"sudo /usr/bin/ssh -i /Users/jenkins/.ssh/localhost -L {server_ip}:{port}:{ip}:22 -N 127.0.0.1 -f"
                VagrantUtils.remote_command(cmd)
                with open(tmp_port_file, 'w') as f:
                    f.write(port)
            else:
                with open(tmp_port_file, 'r') as f:
                    port = f.read()
            ssh_config['port'] = port
            ssh_config['hostname'] = server_ip
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
        if isinstance(command, str):
            command = [command]
        if self.host_identifier:
            cmd = f"sudo VAGRANT_CWD={self.host_identifier} /usr/local/bin/vagrant " + ' '.join(command)
            output = VagrantUtils.remote_command(cmd)
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
