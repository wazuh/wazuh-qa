import yaml, json
import subprocess
import boto3

from pathlib import Path
from telnetlib import Telnet

from .aws.provider import AWSProvider, AWSConfig
from .generic import Instance, Provider, models
from .generic.utils import logger
from .vagrant.provider import VagrantProvider, VagrantConfig


PROVIDERS = {'vagrant': VagrantProvider, 'aws': AWSProvider}
CONFIGS = {'vagrant': VagrantConfig, 'aws': AWSConfig}


class Allocator:
    """
    Allocator class to manage instances based on the payload action.
    """
    @classmethod
    def run(cls, payload: models.InputPayload) -> None:
        """
        Executes the appropriate method based on the payload action.

        Args:
            payload (InputPayload): The payload containing the action parameters.
        """
        payload = models.InputPayload(**dict(payload))
        # Detect the action and call the appropriate method.
        if payload.action == 'create':
            logger.info(f"Creating instance at {payload.working_dir}")
            return cls.__create(payload)
        elif payload.action == 'delete':
            logger.info(f"Deleting instance from trackfile {payload.track_output}")
            return cls.__delete(payload)

    # Internal methods

    @classmethod
    def __create(cls, payload: models.CreationPayload):
        """
        Creates an instance and generates the inventory and track files.

        Args:
            payload (CreationPayload): The payload containing the parameters
                                        for instance creation.
        """
        instance_params = models.CreationPayload(**dict(payload))
        if payload.composite_name.startswith('macos'):
            payload.provider = cls.__macos_provider(payload.composite_name)
        provider: Provider = PROVIDERS[payload.provider]()
        config = cls.___get_custom_config(payload)
        instance = provider.create_instance(
            payload.working_dir, instance_params, config, payload.ssh_key)
        logger.info(f"Instance {instance.identifier} created.")
        # Start the instance.
        instance.start()
        logger.info(f"Instance {instance.identifier} started.")
        # Generate the inventory and track files.
        cls.__generate_inventory(instance, payload.inventory_output)
        cls.__generate_track_file(instance, payload.provider, payload.track_output)

    @classmethod
    def __delete(cls, payload: models.DeletionPayload) -> None:
        """
        Deletes an instance based on the data from the track file.

        Args:
            payload (DeletionPayload): The payload containing the parameters
                                                for instance deletion.
        """
        payload = models.DeletionPayload(**dict(payload))
        # Read the data from the track file.
        with open(payload.track_output, 'r') as f:
            track = models.TrackOutput(**yaml.safe_load(f))
        provider = PROVIDERS[track.provider]()
        provider.destroy_instance(track.instance_dir, track.identifier, track.key_path, track.host_identifier, track.ssh_port)
        logger.info(f"Instance {track.identifier} deleted.")

    @staticmethod
    def ___get_custom_config(payload: models.CreationPayload) -> models.ProviderConfig | None:
        """
        Gets the custom configuration from a file.

        Args:
            payload (CreationPayload): The payload containing the parameters
                                        for instance creation.

        Returns:
            ProviderConfig: The configuration object.
        """
        config = payload.custom_provider_config
        if not config:
            return None
        # Read the custom config file and validate it.
        config_model: models.ProviderConfig = CONFIGS[payload.provider]
        with open(config, 'r') as f:
            logger.info(f"Using custom provider config from {config}")
            config = config_model(**yaml.safe_load(f))
        return config

    @staticmethod
    def __generate_inventory(instance: Instance, inventory_path: Path) -> None:
        """
        Generates an inventory file.

        Args:
            instance (Instance): The instance for which the inventory file is generated.
            inventory_path (Path): The path where the inventory file will be generated.
        """
        inventory_path = Path(inventory_path)
        if not inventory_path.parent.exists():
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
        ssh_config = instance.ssh_connection_info()
        inventory = models.InventoryOutput(ansible_host=ssh_config.hostname,
                                            ansible_user=ssh_config.user,
                                            ansible_port=ssh_config.port,
                                            ansible_ssh_private_key_file=str(ssh_config.private_key),
                                            ansible_password=str(ssh_config.password))
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory.model_dump(), f)
        logger.info(f"SSH connection string: ssh {ssh_config.user}@{ssh_config.hostname} -p {ssh_config.port} -i {ssh_config.private_key}")
        logger.info(f"Inventory file generated at {inventory_path}")

    @staticmethod
    def __generate_track_file(instance: Instance, provider_name: str,  track_path: Path) -> None:
        """
        Generates a track file.

        Args:
            instance (Instance): The instance for which the track file is to be generated.
            provider_name (str): The name of the provider.
            track_path (Path): The path where the track file will be generated.
        """
        track_path = Path(track_path)
        if not track_path.parent.exists():
            track_path.parent.mkdir(parents=True, exist_ok=True)
        ssh_config = instance.ssh_connection_info()
        track = models.TrackOutput(identifier=instance.identifier,
                                    provider=provider_name,
                                    instance_dir=str(instance.path),
                                    key_path=str(instance.credentials.key_path),
                                    host_identifier=str(instance.host_identifier),
                                    ssh_port=ssh_config.port)
        with open(track_path, 'w') as f:
            yaml.dump(track.model_dump(), f)
        if Path(str(instance.path) + "/port.txt").exists():
            Path(str(instance.path) + "/port.txt").unlink()
        logger.info(f"Track file generated at {track_path}")

    @staticmethod
    def __macos_provider(composite_name: str) -> str:
        """
        Returns the provider name for macOS instances.

        Args:
            composite_name (str): The name of the composite.

        Returns:
            str: The provider name.
        """
        if str(composite_name.split("-")[3]) == 'arm64':
            client = boto3.client('secretsmanager')
            server_ip = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_ip')['SecretString']
            server_port = 22
            timeout = 5

            conn_ok = False
            try:
                tn = Telnet(server_ip, server_port, timeout)
                conn_ok = True
                tn.close()
            except Exception as e:
                logger.info('Could not connect to macOS macStadium server: ' + str(e) + '. Using AWS provider.')

            if conn_ok:
                ssh_password = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_password')['SecretString']
                ssh_user = client.get_secret_value(SecretId='devops_macstadium_m1_jenkins_user')['SecretString']
                cmd = "sudo /usr/local/bin/prlctl list -j"
                prlctl_output = subprocess.Popen(f"sshpass -p {ssh_password} ssh {ssh_user}@{server_ip} {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                data_list = json.loads(prlctl_output)
                uuid_count = 0
                for item in data_list:
                    if 'uuid' in item:
                        uuid_count += 1
                if uuid_count < 2:
                    logger.info(f"macStadium server has less than 2 VMs running, using Vagrant provider.")
                    return 'vagrant'
                else:
                    logger.info(f"macStadium server has VMs running, using AWS provider.")
                    return 'aws'
        if str(composite_name.split("-")[3]) == 'amd64':
            return 'aws'
