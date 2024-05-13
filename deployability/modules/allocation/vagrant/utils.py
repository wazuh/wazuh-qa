# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import subprocess
from pathlib import Path
from modules.allocation.generic.utils import logger


class VagrantUtils:
    @classmethod
    def remote_command(cls, command: str | list, remote_host_parameters: dict) -> str:
        """
        Runs a command on the remote host.
        Args:
            command (str | list): The command to run.
            remote_host_parameters (dict): The parameters of the remote host.
        Returns:
            str: The output of the command.
        """
        ssh_command = None
        server_ip = remote_host_parameters['hostname']
        ssh_user = remote_host_parameters['user']
        if remote_host_parameters.get('password'):
            ssh_password = remote_host_parameters['password']
            ssh_command = f"sshpass -p {ssh_password} ssh -o 'StrictHostKeyChecking no' {ssh_user}@{server_ip} {command}"
        if remote_host_parameters.get('ssh_key'):
            ssh_key = remote_host_parameters['ssh_key']
            ssh_command = f"ssh -o 'StrictHostKeyChecking no' -i {ssh_key} {ssh_user}@{server_ip} \"{command}\""

        try:
            output = subprocess.Popen(f"{ssh_command}",
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
            stdout_data, stderr_data = output.communicate()  # Capture stdout and stderr data
            stdout_text = stdout_data.decode('utf-8') if stdout_data else ""  # Decode stdout bytes to string
            stderr_text = stderr_data.decode('utf-8') if stderr_data else ""  # Decode stderr bytes to string

            if stderr_text:
                logger.error(f"Command failed: {stderr_text}")
                return None

            return stdout_text
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr.decode('utf-8')}")
            return None

    @classmethod
    def remote_copy(cls, instance_dir: Path, host_instance_dir: Path, remote_host_parameters: dict) -> str:
        """
        Copies the instance directory to the remote host.

        Args:
            instance_dir (Path): The instance directory.
            host_instance_dir (Path): The remote directory.
            remote_host_parameters (dict): The parameters of the remote host.

        Returns:
            str: The output of the command.
        """
        server_ip = remote_host_parameters['hostname']
        ssh_password = remote_host_parameters['password']
        ssh_user = remote_host_parameters['user']

        try:
            output = subprocess.Popen(f"sshpass -p {ssh_password} scp -r {instance_dir} {ssh_user}@{server_ip}:{host_instance_dir}",
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
            _, stderr = output.communicate()
            if stderr:
                raise ValueError(f"Command failed: {stderr.decode('utf-8')}")
            return output.stdout
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Command failed: {e.stderr.decode('utf-8')}")

    @classmethod
    def get_port(cls, remote_host_parameters: dict, arch: str = None) -> int:
        """
        Returns the port for the remote host.

        Args:
            remote_host_parameters (dict): The parameters of the remote host.
            arch (str): The architecture of the remote host.

        Returns:
            int: The port.
        """

        if arch == 'ppc64':
            cmd = "sudo lsof -i:8080"
            output = cls.remote_command(cmd, remote_host_parameters)
            if not output:
                return str(8080)
            cmd = "sudo lsof -i:2222"
            output = cls.remote_command(cmd, remote_host_parameters)
            if not output:
                return str(2222)

            raise ValueError(f"ppc64 server has no available SSH ports.")
        else:
            for i in range(20, 40):
                port = f"432{i}"
                cmd = f"sudo lsof -i:{port}"
                output = cls.remote_command(cmd, remote_host_parameters)
                if not output:
                    return port

    @classmethod
    def ssh_copy_id(cls, remote_host_parameters: dict, key: Path) -> str:
        """
        Copies the SSH key to the remote host.

        Args:
            remote_host_parameters (dict): The parameters of the remote host.
            key (Path): The SSH key.

        Returns:
            str: The output of the command.
        """

        server_ip = remote_host_parameters['hostname']
        ssh_user = remote_host_parameters['user']
        ssh_password = remote_host_parameters['password']
        port = remote_host_parameters['port']
        ssh_command = f"sshpass -p {ssh_password} ssh-copy-id -i {key} -p {port} -o 'StrictHostKeyChecking no' -f {ssh_user}@{server_ip}"
        logger.debug(f"Setting up SSH key on VM")

        try:
            output = subprocess.Popen(f"{ssh_command}",
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
            stdout_data, stderr_data = output.communicate()  # Capture stdout and stderr data
            stdout_text = stdout_data.decode('utf-8') if stdout_data else ""  # Decode stdout bytes to string
            return stdout_text
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr.decode('utf-8')}")
            return None
