import os
import platform, json
import subprocess
import boto3

from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from telnetlib import Telnet

from modules.allocation.generic import Provider
from modules.allocation.generic.models import CreationPayload
from modules.allocation.generic.utils import logger
from .credentials import VagrantCredentials
from .instance import VagrantInstance
from .models import VagrantConfig
from .utils import VagrantUtils


class VagrantProvider(Provider):
    """
    The VagrantProvider class is a provider for managing Vagrant instances.
    It inherits from the generic Provider class.

    Attributes:
        provider_name (str): Name of the provider ('vagrant').
    """
    provider_name = 'vagrant'

    @classmethod
    def _create_instance(cls, base_dir: Path, params: CreationPayload, config: VagrantConfig = None, ssh_key: str = None) -> VagrantInstance:
        """
        Creates a Vagrant instance.

        Args:
            base_dir (Path): The base directory for the instance.
            params (CreationPayload): The parameters for instance creation.
            config (VagrantConfig, optional): The configuration for the instance. Defaults to None.
            ssh_key (str, optional): Public or private key for the instance. For example, we assume that if the public key is provided, the private key is located in the same directory and has the same name as the public key. Defaults to None.

        Returns:
            VagrantInstance: The created Vagrant instance.
        """
        if params.instance_name:
            instance_id = params.instance_name
        else:
            instance_id = cls._generate_instance_id(cls.provider_name)
        # Create the instance directory.
        instance_dir = base_dir / instance_id
        instance_dir.mkdir(parents=True, exist_ok=True)
        platform = str(params.composite_name.split("-")[0])
        host_instance_dir = None
        host_identifier = None
        macos_host_parameters = None
        arch = str(params.composite_name.split("-")[3])
        # Used for macOS deployments
        if platform == 'macos':
            host_instance_dir = "/Users/jenkins/testing/" + instance_id
            logger.debug(f"Creating instance directory on remote host")
            cmd = f"mkdir {host_instance_dir}"
            macos_host_parameters = cls.__macos_host(arch, 'create')
            host_identifier = macos_host_parameters['host_provider']
            VagrantUtils.remote_command(cmd, macos_host_parameters)
        credentials = VagrantCredentials()
        if not config:
            logger.debug(f"No config provided. Generating from payload")
            # Keys.
            if not ssh_key:
                logger.debug(f"Generating new key pair")
                credentials.generate(instance_dir, 'instance_key')
            else:
                logger.debug(f"Using provided key pair")
                public_key = credentials.ssh_key_interpreter(ssh_key)
                credentials.load(public_key)
            # Parse the config if it is not provided.
            config = cls.__parse_config(params, credentials, instance_id, instance_dir, macos_host_parameters)
        else:
            logger.debug(f"Using provided config")
            credentials.load(config.public_key)
        # Create the Vagrantfile.
        cls.__create_vagrantfile(instance_dir, config)
        logger.debug(f"Vagrantfile created. Creating instance.")
        if platform == 'macos':
            vagrant_file = str(instance_dir) + '/Vagrantfile'
            VagrantUtils.remote_copy(vagrant_file, host_instance_dir, macos_host_parameters)
        return VagrantInstance(instance_dir, instance_id, platform, credentials, host_identifier, host_instance_dir, macos_host_parameters, arch, ssh_port=None)

    @staticmethod
    def _load_instance(instance_dir: Path, identifier: str) -> VagrantInstance:
        """
        Loads a Vagrant instance.

        Args:
            instance_dir (Path): The directory of the instance.
            identifier (str): The identifier of the instance.

        Returns:
            VagrantInstance: The loaded Vagrant instance.
        """
        return VagrantInstance(instance_dir, identifier)

    @classmethod
    def _destroy_instance(cls, instance_dir: Path, identifier: str, key_path: str, platform: str, host_identifier: str = None, host_instance_dir: str | Path = None, ssh_port: str = None, arch: str = None) -> None:
        """
        Destroys a Vagrant instance.

        Args:
            instance_dir (Path): The directory of the instance.
            identifier (str): The identifier of the instance.
            key_path (str): The path of the key for the instance.
            platform (str): The platform of the instance.
            host_identifier (str, optional): The host for the instance. Defaults to None.
            host_instance_dir (str | Path, optional): The remote directory of the instance. Defaults to None.
            ssh_port (str, optional): The SSH port of the instance. Defaults to None.
            arch (str): The architecture of the instance.
        Returns:
            None
        """
        if host_identifier == "None" or host_identifier is None:
            instance = VagrantInstance(instance_dir, identifier, platform)
            if os.path.dirname(key_path) != str(instance_dir):
                logger.debug(f"The key {key_path} will not be deleted. It is the user's responsibility to delete it.")
        else:
            macos_host_parameters = cls.__macos_host(str(arch), 'delete')
            instance = VagrantInstance(instance_dir, identifier, platform, None, host_identifier, host_instance_dir, macos_host_parameters, arch, ssh_port)
        logger.debug(f"Destroying instance {identifier}")
        instance.delete()

    @classmethod
    def __create_vagrantfile(cls, instance_dir: Path, config: VagrantConfig) -> None:
        """
        Creates a Vagrantfile in the instance directory.

        Args:
            instance_dir (Path): The directory to create the Vagrantfile in.
            config (VagrantConfig): The configuration for the Vagrantfile.

        Returns:
            None
        """
        if 'win' in platform.system().lower():
            # Add dobule backslashes for windows.
            config.public_key = config.public_key.replace('\\', '\\\\')
        content = cls.__render_vagrantfile(config)
        with open(instance_dir / 'Vagrantfile', 'w') as f:
            f.write(content)

    @classmethod
    def __render_vagrantfile(cls, config: VagrantConfig) -> str:
        """
        Renders a Vagrantfile template.

        Args:
            config (VagrantConfig): The configuration for the Vagrantfile.

        Returns:
            str: The rendered Vagrantfile.
        """
        environment = Environment(loader=FileSystemLoader(cls.TEMPLATES_DIR))
        if config.platform == 'macos':
            if config.arch == 'arm64':
                template = environment.get_template("vagrant_macStadium.j2")
            else:
                template = environment.get_template("vagrant_black_mini.j2")
        else:
            template = environment.get_template("vagrant.j2")
        return template.render(config=config)

    @classmethod
    def __parse_config(cls, params: CreationPayload, credentials: VagrantCredentials, instance_id: str, instance_dir: Path, macos_host_parameters: dict = None) -> VagrantConfig:
        """
        Parses the configuration for a Vagrant instance.

        Args:
            params (CreationPayload): The parameters for instance creation.
            credentials (VagrantCredentials): The credentials for the instance.

        Returns:
            VagrantConfig: The parsed configuration for the Vagrant instance.
        """
        config = {}
        # Get the specs from the yamls.
        size_specs = cls._get_size_specs()[params.size]
        os_specs = cls._get_os_specs()[params.composite_name]
        # Parse the configuration.
        config['ip'] = cls.__get_available_ip()
        config['box'] = os_specs['box']
        config['box_version'] = os_specs['box_version']
        config['private_key'] = str(credentials.key_path)
        config['public_key'] = str(credentials.key_path.with_suffix('.pub'))
        config['cpu'] = size_specs['cpu']
        config['memory'] = size_specs['memory']
        config['name'] = instance_id
        config['platform'] = params.composite_name.split("-")[0]
        config['arch'] = params.composite_name.split("-")[3]

        if params.composite_name.startswith("macos") and params.composite_name.endswith("amd64"):
            tmp_port_file = str(instance_dir) + "/port.txt"
            config['port'] = VagrantUtils.get_port(macos_host_parameters)
            with open(tmp_port_file, 'w') as f:
                f.write(config['port'])

        return VagrantConfig(**config)

    @classmethod
    def __get_available_ip(cls):
        """
        Gets an available IP address.

        Returns:
            str: An available IP address.

        Raises:
            Exception: If no available IP address is found.
        """
        def check_ip(ip):
            response = os.system("ping -c 1 -w3 " + ip + " > /dev/null 2>&1")
            if response != 0:
                return ip

        for i in range(2, 254):
            ip = f"192.168.57.{i}"
            if check_ip(ip):
                return ip

        # If no available IP address is found, raise an exception.
        raise cls.ProvisioningError("No available IP address found.")

    @staticmethod
    def __macos_host(arch: str, action: str) -> str:
        """
        Returns the host parameters for macOS instances.

        Args:
            arch (str): The architecture of the instance.

        Returns:
            str: The provider name.
        """
        client = boto3.client('secretsmanager')
        server_port = 22
        timeout = 5
        conn_ok = False
        macos_host_parameters = {}

        if arch == 'arm64':
            try:
                server_ip = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_ip')['SecretString']
                ssh_password = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_password')['SecretString']
                ssh_user = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_user')['SecretString']
            except Exception as e:
                logger.error('Could not get macOS macStadium server IP: ' + str(e) + '.')
                exit(1)

            try:
                tn = Telnet(server_ip, server_port, timeout)
                conn_ok = True
                tn.close()
            except Exception as e:
                logger.error('Could not connect to macOS macStadium server: ' + str(e) + '.')
                exit(1)

            macos_host_parameters['server_ip'] = server_ip
            macos_host_parameters['ssh_password'] = ssh_password
            macos_host_parameters['ssh_user'] = ssh_user
            macos_host_parameters['host_provider'] = 'macstadium'

            if conn_ok:
                if action == 'create':
                    cmd = "sudo /usr/local/bin/prlctl list -j"
                    prlctl_output = subprocess.Popen(f"sshpass -p {ssh_password} ssh {ssh_user}@{server_ip} {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                    data_list = json.loads(prlctl_output)
                    uuid_count = 0
                    for item in data_list:
                        if 'uuid' in item:
                            uuid_count += 1
                    if uuid_count < 2:
                        logger.info(f"macStadium server has less than 2 VMs running, deploying in this host.")
                        return macos_host_parameters
                    else:
                        logger.error(f"macStadium server is full capacity, use AWS provider.")
                        exit(1)
                else:
                    return macos_host_parameters
        if arch == 'amd64':
            try:
                server_ip = client.get_secret_value(SecretId='devops_black_mini_jenkins_ip')['SecretString']
                ssh_password = client.get_secret_value(SecretId='devops_black_mini_jenkins_password')['SecretString']
                ssh_user = client.get_secret_value(SecretId='devops_black_mini_jenkins_user')['SecretString']
            except Exception as e:
                logger.error('Could not get macOS Black mini server IP: ' + str(e) + '.')
                exit(1)

            try:
                tn = Telnet(server_ip, server_port, timeout)
                conn_ok = True
                tn.close()
            except Exception as e:
                logger.error('Could not connect to macOS Black mini server: ' + str(e) + '.')
                exit(1)

            macos_host_parameters['server_ip'] = server_ip
            macos_host_parameters['ssh_password'] = ssh_password
            macos_host_parameters['ssh_user'] = ssh_user
            macos_host_parameters['host_provider'] = 'black_mini'

            if conn_ok:
                if action == 'create':
                    loadav_command = "\'python3 -c \"import psutil; print(psutil.getloadavg()[0])\"\'"
                    cpu_command = "\'python3 -c \"import psutil; print(psutil.getloadavg()[0]/ psutil.cpu_count() * 100)\"\'"
                    memory_command = "\'python3 -c \"import psutil; print(psutil.virtual_memory().percent)\"\'"
                    load_average = subprocess.Popen(f"sshpass -p {ssh_password} ssh {ssh_user}@{server_ip} {loadav_command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                    cpu_usage = subprocess.Popen(f"sshpass -p {ssh_password} ssh {ssh_user}@{server_ip} {cpu_command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                    memory_usage = subprocess.Popen(f"sshpass -p {ssh_password} ssh {ssh_user}@{server_ip} {memory_command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')

                    if float(load_average) <= 10.0 and float(cpu_usage) <= 70.0 and float(memory_usage) <= 75.0:
                        logger.info(f"Using the black mini server to deploy.")
                        return macos_host_parameters
                    else:
                        logger.error(f"Black mini server is under heavy load, use AWS provider.")
                        exit(1)
                else:
                    return macos_host_parameters
