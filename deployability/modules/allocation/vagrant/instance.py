# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import subprocess

from pathlib import Path

from modules.allocation.generic import Instance
from modules.allocation.generic.models import ConnectionInfo, InstancePayload
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
        remote_host_parameters (dict): Parameters of the remote host.
    """
    def __init__(self, instance_parameters: InstancePayload, credentials: VagrantCredentials = None) -> None:
        """
        Initializes a VagrantInstance.

        Args:
            instance_parameters (InstancePayload): The parameters of the instance.
            credentials (VagrantCredentials, optional): The credentials of the instance. Defaults to None.
        """
        super().__init__(instance_parameters, credentials)
        self.path: Path = Path(instance_parameters.instance_dir)
        self.identifier: str = instance_parameters.identifier
        self.credentials: VagrantCredentials = credentials
        self.host_identifier: str = instance_parameters.host_identifier
        self.host_instance_dir: str | Path = instance_parameters.host_instance_dir
        self.ssh_port: str = instance_parameters.ssh_port
        self.remote_host_parameters: dict = instance_parameters.remote_host_parameters
        self.platform: str = instance_parameters.platform
        self.arch: str = instance_parameters.arch
        self.docker_image: str = instance_parameters.docker_image
        self.virtualizer: str = instance_parameters.virtualizer

    def start(self) -> None:
        """
        Starts the Vagrant virtual machine.

        Returns:
            None
        """
        if self.arch == 'ppc64':
            cmd = f"sudo docker run -itd --name={self.identifier} -p {self.ssh_port}:22 {self.docker_image}"
            output = VagrantUtils.remote_command(cmd, self.remote_host_parameters)
            container_id = output.split("\n")[0]
            public_key = subprocess.run(["cat", str(self.credentials.key_path) + ".pub"],
                                        stdout=subprocess.PIPE).stdout.decode("utf-8")
            public_key = public_key.strip("\n")
            cmd = f"sudo docker exec -i {container_id} /bin/bash -c 'echo \"{public_key}\" >> /root/.ssh/authorized_keys'"
            output = VagrantUtils.remote_command(cmd, self.remote_host_parameters)
            return output
        else:
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
        if str(self.arch) == 'ppc64':
            cmd = f"sudo docker rm -f {self.identifier}"
            VagrantUtils.remote_command(cmd, self.remote_host_parameters)
            return
        if "not created" in self.status():
            logger.warning(f"Instance {self.identifier} is not created.\
                            Skipping deletion.")
            return
        self.__run_vagrant_command(['destroy', '-f'])
        if str(self.host_identifier) == "macstadium":
            self.__cleanup_remote_host()

    def status(self) -> str:
        """
        Checks the status of the Vagrant virtual machine.

        Returns:
            str: The status of the instance.
        """
        output = self.__run_vagrant_command('status')
        vagrant_status = self.__parse_vagrant_status(output)
        if vagrant_status is None:
            if self.remote_host_parameters['server_ip'] == None:
                raise ValueError(f"Cannot obtain the status of the instance {self.identifier}, please remove the instance manually.")
            else:
                output = VagrantUtils.remote_command(f"sudo test -d {self.host_instance_dir} && echo 'Directory exists' || echo 'Directory does not exist'", self.remote_host_parameters)
                if 'Directory exists' in output:
                    if VagrantUtils.remote_command(f"sudo /usr/local/bin/prlctl list -a | grep {self.identifier}", self.remote_host_parameters):
                        logger.warning(f"The instance was found, it will be deleted. The creation of the instance must be retried.")
                        self.__run_vagrant_command(['destroy', '-f'])
                        self.__cleanup_remote_host()
                        raise ValueError(f"Cannot obtain the status of the instance {self.identifier}, the creation of the instance must be retried.")
                    else:
                        VagrantUtils.remote_command(f"sudo rm -rf {self.host_instance_dir}", self.remote_host_parameters)
                        raise ValueError(f"Instance {self.identifier} is not running, remote instance dir {self.host_instance_dir} was removed. The creation of the instance must be retried.")
                else:
                    raise ValueError(f"Instance {self.host_instance_dir} not found. The creation of the instance must be retried.")
        else:
            return vagrant_status

    def ssh_connection_info(self) -> ConnectionInfo:
        """
        Returns the SSH configuration of the Vagrant virtual machine.

        Returns:
            ConnectionInfo: The SSH configuration of the VM.
        """
        # Parse the ssh-config.
        ssh_config = {}
        if self.arch == 'ppc64':
            ssh_config['hostname'] = self.remote_host_parameters['server_ip']
            tmp_port_file = str(self.path) + "/port.txt"
            with open(tmp_port_file, 'r') as f:
                port = f.read()
            ssh_config['port'] = port
            ssh_config['user'] = 'root'
            if self.credentials:
                ssh_config['private_key'] = str(self.credentials.key_path)
        else:
            if not 'running' in self.status():
                logger.debug(f"Instance {self.identifier} is not running.\
                                Starting it.")
                self.start()
            output = self.__run_vagrant_command('ssh-config')
            patterns = {'hostname': r'HostName (.*)',
                        'user': r'User (.*)',
                        'port': r'Port (.*)',
                        'private_key': r'IdentityFile (.*)'}
            if self.platform == 'macos':
                for key, pattern in patterns.items():
                    match = re.search(pattern, output)
                    if match and key == 'hostname':
                        ip = match.group(1).strip()
                server_ip = self.remote_host_parameters['server_ip']
                tmp_port_file = str(self.path) + "/port.txt"
                if str(self.host_identifier) == "macstadium":
                    if not Path(tmp_port_file).exists():
                        port = VagrantUtils.get_port(self.remote_host_parameters)
                        cmd = f"/usr/bin/ssh -i /Users/jenkins/.ssh/localhost -L {server_ip}:{port}:{ip}:22 -N 127.0.0.1 -f"
                        VagrantUtils.remote_command(cmd, self.remote_host_parameters)
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
                ssh_config['port'] = 5985
                ssh_config['user'] = 'vagrant'
                ssh_config['password'] = 'vagrant'
            else:
                for key, pattern in patterns.items():
                    match = re.search(pattern, output)
                    if not match:
                        logger.error(f"Couldn't find {key} in ssh-config")
                        return None
                    ssh_config[key] = str(match.group(1)).strip("\r")
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
            cmd = f"sudo {self.host_instance_dir}/vagrant_script.sh " + ' '.join(command)
            output = VagrantUtils.remote_command(cmd, self.remote_host_parameters)
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
        if message is None:
            logger.error("Received None message when parsing Vagrant status")
            return None

        lines = message.split('\n')
        for line in lines:
            if 'Current machine states:' in line:
                status_line = lines[lines.index(line) + 2]
                status = ' '.join(status_line.split()[1:])
                status = status.split('(')[0].strip()
                return status

    def __cleanup_remote_host(self) -> None:
        """
        Cleans up the remote host.

        Returns:
            None
        """
        logger.debug(f"Deleting remote directory {self.host_instance_dir}")
        VagrantUtils.remote_command(f"sudo rm -rf {self.host_instance_dir}", self.remote_host_parameters)
        if self.virtualizer == 'parallels':
            logger.debug(f"Killing remote process on port {self.ssh_port}")
            proccess = VagrantUtils.remote_command(f"sudo lsof -Pi :{self.ssh_port} -sTCP:LISTEN -t", self.remote_host_parameters)
            VagrantUtils.remote_command(f"sudo kill -9 {proccess}", self.remote_host_parameters)
