# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import platform, json
import subprocess
import boto3
import random
import re

from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from telnetlib import Telnet

from modules.allocation.generic import Provider
from modules.allocation.generic.models import CreationPayload, InstancePayload, InstancePayload
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
        cls.validate_dependencies(params.composite_name)
        if params.instance_name:
            name = params.instance_name
        elif params.label_issue:
            issue = params.label_issue
            url_regex = "(https:\/\/|http:\/\/)?[github]{2,}(\.[com]{2,})?\/wazuh\/[a-zA-Z0-9_-]+(?:-[a-zA-Z0-9_-]+)?\/issues\/[0-9]{2,}"
            if not re.match(url_regex, issue):
                raise ValueError(f"The issue label was not provided or is of incorrect format, example: https://github.com/wazuh/<repository>/issues/<issue-number>")
            issue_name= re.search(r'github\.com\/wazuh\/([^\/]+)\/issues', issue)
            repository = cls.generate_repository_name(str(issue_name.group(1)))
            name = repository + "-" + str(re.search(r'(\d+)$', issue).group(1)) + "-" + str(params.composite_name.split("-")[1]) + "-" + str(params.composite_name.split("-")[2])
        else:
            raise ValueError("Either --instance-name or --label-issue parameter is required.")

        instance_id = name + "-" + str(random.randint(0000, 9999))
        # Create the instance directory.
        while True:
            try:
                instance_dir = base_dir / instance_id
                instance_dir.mkdir(parents=True)
                break
            except FileExistsError:
                logger.debug(f"Instance directory {instance_dir} already exists. Assigning new suffix.")
                instance_id = name + "-" + str(random.randint(0000, 9999))
        platform = str(params.composite_name.split("-")[0])
        host_instance_dir = None
        host_identifier = None
        remote_host_parameters = None
        arch = str(params.composite_name.split("-")[3])
        # Used for macOS deployments
        if platform == 'macos':
            host_instance_dir = "/Users/jenkins/testing/" + instance_id
            remote_host_parameters = cls.__remote_host(arch, 'create')
            host_identifier = remote_host_parameters['host_provider']
            logger.debug(f"Checking if instance directory exists on remote host")
            cmd = f"ls {host_instance_dir} > /dev/null 2>&1"
            if VagrantUtils.remote_command(cmd, remote_host_parameters):
                raise ValueError(f"Instance directory {host_instance_dir} already exists on remote host. Check if it is possible to delete the directory on the remote host.")
            logger.debug(f"Creating instance directory on remote host")
            cmd = f"mkdir {host_instance_dir}"
            VagrantUtils.remote_command(cmd, remote_host_parameters)
        credentials = VagrantCredentials()
        if arch == 'ppc64':
            remote_host_parameters = cls.__remote_host(arch, 'create', params.composite_name.split("-")[1], instance_dir)
            host_identifier = remote_host_parameters['host_provider']
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
            config = cls.__parse_config(params, credentials, instance_id, instance_dir, remote_host_parameters)
        else:
            logger.debug(f"Using provided config")
            credentials.load(config.public_key)

        if arch != 'ppc64':
            # Create the Vagrantfile.
            cls.__create_vagrantfile(instance_dir, config)
            logger.debug(f"Vagrantfile created. Creating instance.")
        if platform == 'macos':
            vagrant_file = str(instance_dir) + '/Vagrantfile'
            VagrantUtils.remote_copy(vagrant_file, host_instance_dir, remote_host_parameters)
            VagrantUtils.remote_copy(Path(__file__).parent.parent / 'vagrant' / 'helpers' / 'vagrant_script.sh', host_instance_dir, remote_host_parameters)
            cmd = f"chmod 700 {host_instance_dir}/vagrant_script.sh"
            VagrantUtils.remote_command(cmd, remote_host_parameters)

        instance_params = {}
        instance_params['instance_dir'] = instance_dir
        instance_params['identifier'] = instance_id
        instance_params['name'] = config.name
        instance_params['platform'] = platform
        instance_params['host_identifier'] = host_identifier
        instance_params['host_instance_dir'] = host_instance_dir
        instance_params['remote_host_parameters'] = remote_host_parameters
        instance_params['arch'] = arch
        instance_params['docker_image'] = config.box
        instance_params['ssh_port'] = config.port
        instance_params['virtualizer'] = config.virtualizer
        return VagrantInstance(InstancePayload(**instance_params), credentials)

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
        instance_params = InstancePayload(**dict(instance_dir, identifier))
        return VagrantInstance(instance_params)

    @classmethod
    def _destroy_instance(cls, destroy_parameters: InstancePayload) -> None:
        """
        Destroys a Vagrant instance.

        Args:
            destroy_parameters (InstancePayload): The parameters for instance deletion.
        Returns:
            None
        """
        if destroy_parameters.host_identifier == "None" or destroy_parameters.host_identifier is None:
            instance_params = {}
            instance_params['instance_dir'] = destroy_parameters.instance_dir
            instance_params['identifier'] = destroy_parameters.identifier
            instance_params['platform'] = destroy_parameters.platform
            instance = VagrantInstance(InstancePayload(**instance_params))
            if os.path.dirname(destroy_parameters.key_path) != str(destroy_parameters.instance_dir):
                logger.debug(f"The key {destroy_parameters.key_path} will not be deleted. It is the user's responsibility to delete it.")
        else:
            instance_params = {}
            instance_params['instance_dir'] = destroy_parameters.instance_dir
            instance_params['identifier'] = destroy_parameters.identifier
            instance_params['platform'] = destroy_parameters.platform
            instance_params['host_identifier'] = destroy_parameters.host_identifier
            instance_params['host_instance_dir'] = destroy_parameters.host_instance_dir
            remote_host_parameters = cls.__remote_host(str(destroy_parameters.arch), 'delete', destroy_parameters.host_identifier, destroy_parameters.instance_dir)
            instance_params['remote_host_parameters'] = remote_host_parameters
            instance_params['arch'] = destroy_parameters.arch
            instance_params['ssh_port'] = destroy_parameters.ssh_port
            instance_params['virtualizer'] = destroy_parameters.virtualizer
            instance = VagrantInstance(InstancePayload(**instance_params))
        logger.debug(f"Destroying instance {destroy_parameters.identifier}")
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
            if config.arch == 'amd64':
                if config.virtualizer == 'parallels':
                    template = environment.get_template("vagrant_parallels_intel.j2")
                else:
                    template = environment.get_template("vagrant_Virtual_box.j2")
            else:
                template = environment.get_template("vagrant_parallels_arm.j2")
        else:
            template = environment.get_template("vagrant.j2")
        return template.render(config=config)

    @classmethod
    def __parse_config(cls, params: CreationPayload, credentials: VagrantCredentials, instance_id: str, instance_dir: Path, remote_host_parameters: dict = None) -> VagrantConfig:
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
        size_specs = cls._get_size_specs(params.size)
        os_specs = cls._get_os_specs(params.composite_name)
        # Parse the configuration.
        config['ip'] = cls.__get_available_ip()
        config['box'] = str(os_specs['box'])
        config['box_version'] = str(os_specs['box_version'])
        config['virtualizer'] = str(os_specs['virtualizer'])
        config['private_key'] = str(credentials.key_path)
        config['public_key'] = str(credentials.key_path.with_suffix('.pub'))
        config['cpu'] = size_specs['cpu']
        config['memory'] = size_specs['memory']
        config['name'] = instance_id
        config['platform'] = params.composite_name.split("-")[0]
        config['arch'] = params.composite_name.split("-")[3]

        if config['platform'] == 'macos' and config['virtualizer'] == 'virtualbox' or config['virtualizer'] == 'docker':
            tmp_port_file = str(instance_dir) + "/port.txt"
            config['port'] = VagrantUtils.get_port(remote_host_parameters, config['arch'])
            with open(tmp_port_file, 'w') as f:
                f.write(config['port'])
            config['ip'] = remote_host_parameters['server_ip']

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

        for i in range(254):
            ip = f"192.168.57.{random.randint(2, 253)}"
            if check_ip(ip):
                return ip

        # If no available IP address is found, raise an exception.
        raise cls.ProvisioningError("No available IP address found.")

    @staticmethod
    def __remote_host(arch: str, action: str, os: str = None, instance_dir: Path = None) -> str:
        """
        Returns the host parameters for macOS instances.

        Args:
            arch (str): The architecture of the instance.
            action (str): The action to perform.
            os (str, optional): The operating system of the instance. Defaults to None.
            instance_dir (Path, optional): The directory of the instance. Defaults to None.

        Returns:
            dict: The host parameters for the remote instance.
        """
        client = boto3.client('secretsmanager')
        server_port = 22
        timeout = 5
        conn_ok = False
        remote_host_parameters = {}

        if arch == 'arm64':
            try:
                server_ip = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_ip')['SecretString']
                ssh_password = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_password')['SecretString']
                ssh_user = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_user')['SecretString']
            except Exception as e:
                raise ValueError('Could not get macOS macStadium ARM server IP: ' + str(e) + '.')

            try:
                tn = Telnet(server_ip, server_port, timeout)
                conn_ok = True
                tn.close()
            except Exception as e:
                raise ValueError('Could not connect to macOS macStadium ARM server: ' + str(e) + '.')

            remote_host_parameters['server_ip'] = server_ip
            remote_host_parameters['ssh_password'] = ssh_password
            remote_host_parameters['ssh_user'] = ssh_user
            remote_host_parameters['host_provider'] = 'macstadium'

            if conn_ok:
                if action == 'create':
                    try:
                        cmd = "sudo /usr/local/bin/prlctl list -j"
                        prlctl_output = subprocess.Popen(f"sshpass -p {ssh_password} ssh -o 'StrictHostKeyChecking no' {ssh_user}@{server_ip} {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                        data_list = json.loads(prlctl_output)
                    except Exception as e:
                        raise ValueError('Could not get VMs running on macStadium ARM server: ' + str(e) + '.')
                    uuid_count = 0
                    for item in data_list:
                        if 'uuid' in item:
                            uuid_count += 1
                    if uuid_count < 2:
                        logger.info(f"macStadium ARM server has less than 2 VMs running, deploying in this host.")
                        return remote_host_parameters
                    else:
                        raise ValueError(f"macStadium ARM server is full capacity, use AWS provider.")
                else:
                    return remote_host_parameters
        if arch == 'amd64':
            try:
                server_ip = client.get_secret_value(SecretId='devops_macstadium_intel_ip')['SecretString']
                ssh_password = client.get_secret_value(SecretId='devops_macstadium_intel_password')['SecretString']
                ssh_user = client.get_secret_value(SecretId='devops_macstadium_intel_user')['SecretString']
            except Exception as e:
                raise ValueError('Could not get macOS macStadium Intel server IP: ' + str(e) + '.')

            try:
                tn = Telnet(server_ip, server_port, timeout)
                conn_ok = True
                tn.close()
            except Exception as e:
                raise ValueError('Could not connect to macOS macStadium Intel server: ' + str(e) + '.')

            remote_host_parameters['server_ip'] = server_ip
            remote_host_parameters['ssh_password'] = ssh_password
            remote_host_parameters['ssh_user'] = ssh_user
            remote_host_parameters['host_provider'] = 'macstadium'

            if conn_ok:
                if action == 'create':
                    try:
                        loadav_command = "\'python3 -c \"import psutil; print(psutil.getloadavg()[0])\"\'"
                        cpu_command = "\'python3 -c \"import psutil; print(psutil.getloadavg()[0]/ psutil.cpu_count() * 100)\"\'"
                        memory_command = "\'python3 -c \"import psutil; print(psutil.virtual_memory().percent)\"\'"
                        load_average = subprocess.Popen(f"sshpass -p {ssh_password} ssh -o 'StrictHostKeyChecking no' {ssh_user}@{server_ip} {loadav_command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                        cpu_usage = subprocess.Popen(f"sshpass -p {ssh_password} ssh -o 'StrictHostKeyChecking no' {ssh_user}@{server_ip} {cpu_command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                        memory_usage = subprocess.Popen(f"sshpass -p {ssh_password} ssh -o 'StrictHostKeyChecking no' {ssh_user}@{server_ip} {memory_command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                    except Exception as e:
                        raise ValueError('Could not get server load average: ' + str(e) + '.')

                    if float(load_average) <= 10.0 and float(cpu_usage) <= 70.0 and float(memory_usage) <= 75.0:
                        logger.info(f"Using the macStadium Intel server to deploy.")
                        return remote_host_parameters
                    else:
                        raise ValueError(f"macStadium Intel server is under heavy load, use AWS provider.")
                else:
                    return remote_host_parameters

        if arch == 'ppc64':
            if os == 'debian':
                try:
                    server_ip = client.get_secret_value(SecretId='devops_ppc64_debian_jenkins_ip')['SecretString']
                    ssh_key = client.get_secret_value(SecretId='devops_ppc64_jenkins_key')['SecretString']
                    ssh_user = client.get_secret_value(SecretId='devops_ppc64_debian_jenkins_user')['SecretString']
                    remote_host_parameters['host_provider'] = 'debian'
                except Exception as e:
                    raise ValueError('Could not get Debian ppc64 server IP: ' + str(e) + '.')
            if os == 'centos':
                try:
                    server_ip = client.get_secret_value(SecretId='devops_ppc64_centos_jenkins_ip')['SecretString']
                    ssh_key = client.get_secret_value(SecretId='devops_ppc64_jenkins_key')['SecretString']
                    ssh_user = client.get_secret_value(SecretId='devops_ppc64_centos_jenkins_user')['SecretString']
                    remote_host_parameters['host_provider'] = 'centos'
                except Exception as e:
                    raise ValueError('Could not get CentOS ppc64 server IP: ' + str(e) + '.')

            try:
                tn = Telnet(server_ip, server_port, timeout)
                conn_ok = True
                tn.close()
            except Exception as e:
                raise ValueError('Could not connect to ppc64 server: ' + str(e) + '.')

            key_path = instance_dir / 'ppc-key'
            with open(key_path, 'w') as f:
                f.write(ssh_key)
            ssh_key = key_path
            subprocess.call(['chmod', '0400', key_path])

            remote_host_parameters['server_ip'] = server_ip
            remote_host_parameters['ssh_key'] = ssh_key
            remote_host_parameters['ssh_user'] = ssh_user

            if conn_ok:
                if action == 'create':
                    try:
                        cmd = "sudo docker ps -a"
                        output = subprocess.Popen(f"ssh -i {ssh_key} {ssh_user}@{server_ip} {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                    except Exception as e:
                        raise ValueError('Could not get docker containers running on ppc64 server: ' + str(e) + '.')
                    if '2222' in output and '8080' in output:
                        raise ValueError(f"ppc64 server has full capacity, cannot host a new container")
                    else:
                        return remote_host_parameters
                else:
                    return remote_host_parameters

    @staticmethod
    def validate_dependencies(composite_name: str):
        """
        Validates the dependencies for the Vagrant provider.

        Args:
            composite_name (str): The composite name of the instance.

        Raises:
            ValueError: If the dependencies are not met.
        """
        remote_deploy_dependencies = ['openssh-client', 'sshpass', 'awscli']
        local_deploy_dependencies = ['vagrant', 'virtualbox']
        missing_dependencies = []
        platform = str(composite_name.split("-")[0])
        arch = str(composite_name.split("-")[3])

        result = subprocess.run(['which', 'apt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise ValueError("The Allocation module works on systems with APT as packages systems.")


        if platform == 'macos' or arch == 'ppc64':
            dependencies = remote_deploy_dependencies
        else:
            dependencies = local_deploy_dependencies

        for dependency in dependencies:
            result = subprocess.run(['bash', '-c', f"apt list --installed 2>/dev/null | grep -q -E ^{dependency}*"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                if dependency == 'awscli':
                    aws_binary = subprocess.run(['which', 'aws'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if aws_binary.returncode != 0:
                        missing_dependencies.append(dependency)
                else:
                    missing_dependencies.append(dependency)

        if len(missing_dependencies) > 0:
            if len(missing_dependencies) == 1:
                raise ValueError(f"Missing dependency: {missing_dependencies[0]}")
            else:
                raise ValueError(f"Missing dependencies: {missing_dependencies}")
