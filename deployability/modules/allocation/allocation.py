import yaml

from pathlib import Path

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
        provider: Provider = PROVIDERS[payload.provider]()
        config = cls.___get_custom_config(payload)
        instance = provider.create_instance(
            payload.working_dir, instance_params, config, payload.ssh_key)
        logger.info(f"Instance {instance.identifier} created.")
        # Start the instance
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
        provider.destroy_instance(track.instance_dir, track.identifier, track.key_path)
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
                                            ansible_ssh_private_key_file=str(ssh_config.private_key))
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory.model_dump(), f)
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
        track = models.TrackOutput(identifier=instance.identifier,
                                    provider=provider_name,
                                    instance_dir=str(instance.path),
                                    key_path=str(instance.credentials.key_path))
        with open(track_path, 'w') as f:
            yaml.dump(track.model_dump(), f)
        logger.info(f"Track file generated at {track_path}")
