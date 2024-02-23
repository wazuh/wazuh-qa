import subprocess
import boto3
from pathlib import Path
from modules.allocation.generic.utils import logger


class VagrantUtils:
    @classmethod
    def remote_command(cls, command: str | list) -> str:
        """
        Runs a command on the remote host.
        Args:
            command (str | list): The command to run.
        Returns:
            str: The output of the command.
        """
        client = boto3.client('secretsmanager')
        server_ip = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_ip')['SecretString']
        ssh_password = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_password')['SecretString']
        ssh_user = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_user')['SecretString']

        try:
            output = subprocess.Popen(f"sshpass -p {ssh_password} ssh {ssh_user}@{server_ip} {command}",
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
    def remote_copy(cls, instance_dir: Path, host_identifier: Path) -> str:
        """
        Copies the instance directory to the remote host.

        Args:
            instance_dir (Path): The instance directory.
            host_identifier (Path): The remote directory.

        Returns:
            str: The output of the command.
        """
        client = boto3.client('secretsmanager')
        server_ip = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_ip')['SecretString']
        ssh_password = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_password')['SecretString']
        ssh_user = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_user')['SecretString']

        try:
            output = subprocess.Popen(f"sshpass -p {ssh_password} scp -r {instance_dir} {ssh_user}@{server_ip}:{host_identifier}",
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
            _, stderr = output.communicate()
            if stderr:
                logger.error(f"Command failed: {stderr.decode('utf-8')}")
                return None
            return output.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr.decode('utf-8')}")
            return None

    @classmethod
    def get_port(cls) -> int:
        """
        Returns the port for the remote host.

        Returns:
            int: The port.
        """

        for i in range(20, 40):
            port = f"432{i}"
            cmd = f"sudo lsof -i:{port}"
            output = cls.remote_command(cmd)
            if not output:
                return port
