# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import subprocess
from pathlib import Path
import logging
import random
import socket

import paramiko

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
        ssh = paramiko.SSHClient()
        paramiko.util.get_logger("paramiko").setLevel(logging.WARNING)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_parameters = {
            'hostname': remote_host_parameters['server_ip'],
            'port': 22,
            'username': remote_host_parameters['ssh_user']
        }
        if remote_host_parameters.get('ssh_key'):
            ssh_parameters['key_filename'] = str(remote_host_parameters['ssh_key'])
        else:
            ssh_parameters['password'] = remote_host_parameters['ssh_password']

        max_retry = 3
        ssh_exceptions = (subprocess.CalledProcessError, paramiko.AuthenticationException, paramiko.SSHException, socket.timeout, ConnectionResetError)
        for attempt in range(max_retry):
            try:
                ssh.connect(**ssh_parameters)
                stdin_data, stdout_data, stderr_data = ssh.exec_command(command, timeout = 300)
                stdout_text = stdout_data.read().decode('utf-8')

                ssh.close()
                return stdout_text
            except ssh_exceptions as e:
                if attempt < max_retry - 1:
                    logger.warning(f"SSH connection error: {str(e)}. Retrying in 30 seconds...")
                    time.sleep(30)
                    continue
                else:
                    ssh.close()
                    raise ValueError(f"Remote command execution failed: {str(e)}")
            except Exception as e:
                ssh.close()
                raise ValueError(f"An unexpected error occurred when executing the remote command: {str(e)}")

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
        server_ip = remote_host_parameters['server_ip']
        ssh_password = remote_host_parameters['ssh_password']
        ssh_user = remote_host_parameters['ssh_user']

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
            used_ports = []
            all_ports = [f"432{i}" for i in range(20, 40)]
            random.shuffle(all_ports)
            for port in all_ports:
                if port not in used_ports:
                    cmd = f"sudo lsof -i:{port}"
                    output = cls.remote_command(cmd, remote_host_parameters)
                    if not output:
                        return port
                    else:
                        used_ports.append(port)
            else:
                raise ValueError(f"The server has no available ports in the range 43220 to 43240.")
