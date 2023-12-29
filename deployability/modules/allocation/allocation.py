import yaml

from pathlib import Path

from .instances.generic import Instance
from .models import InputPayload, InventoryOutput, TrackOutput
from .providers import VagrantProvider, AWSProvider, Provider
from .providers.generic import InstanceParams

PROVIDERS = {'vagrant': VagrantProvider, 'aws': AWSProvider}


class Allocator:
    @classmethod
    def run(cls, payload: InputPayload) -> None:
        payload = InputPayload(**dict(payload))
        working_dir = Path(payload.working_dir)
        # Detect the action and call the appropriate method.
        if payload.action == 'create':
            print(f"Creating instance at {working_dir}")
            return cls._create(working_dir, payload)
        elif payload.action == 'delete':
            print(f"Deleting instance from trackfile {payload.track_output}")
            return cls._delete(payload)

    @classmethod
    def _create(cls, path: str, payload: InputPayload):
        provider: Provider = PROVIDERS[payload.provider]()
        instance_params = InstanceParams(**dict(payload))
        instance = provider.create_instance(path, instance_params)
        print(f"Instance {instance.identifier} created.")
        # Start the instance
        instance.start()
        # Generate the inventory and track files.
        cls.__generate_inventory(instance, payload.inventory_output)
        cls.__generate_track_file(instance, payload.provider, payload.track_output)
        # TODO replace with logger
        print(f"\nInventory file generated at {payload.inventory_output}")
        print(f"\nTrack file generated at {payload.track_output}")

    @classmethod
    def _delete(cls, payload: InputPayload) -> None:
        payload = InputPayload(**dict(payload))
        # Validate the track file.
        if not payload.track_output:
            raise ValueError("Track file is required to delete an instance.")
        if not Path(payload.track_output).exists():
            raise ValueError(f"Track file {payload.track_output} does not exist.")
        # Read the data from the track file.
        with open(payload.track_output, 'r') as f:
            track = TrackOutput(**yaml.safe_load(f))
        provider = PROVIDERS[track.provider]()
        provider.destroy_instance(track.instance_dir, track.identifier)

    @staticmethod
    def __generate_inventory(instance: Instance, inventory_path: Path) -> None:
        inventory_path = Path(inventory_path)
        if not inventory_path.parent.exists():
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
        ssh_config = instance.ssh_connection_info()
        inventory = InventoryOutput(ansible_host=ssh_config.hostname,
                                    ansible_user=ssh_config.user,
                                    ansible_port=ssh_config.port,
                                    ansible_ssh_private_key_file=str(ssh_config.private_key))
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory.model_dump(), f)

    @staticmethod
    def __generate_track_file(instance: Instance, provider_name: str,  track_path: Path) -> None:
        track_path = Path(track_path)
        if not track_path.parent.exists():
            track_path.parent.mkdir(parents=True, exist_ok=True)
        track = TrackOutput(identifier=instance.identifier,
                            provider=provider_name,
                            instance_dir=str(instance.path),
                            key_path=str(instance.credentials.key_path))
        with open(track_path, 'w') as f:
            yaml.dump(track.model_dump(), f)
