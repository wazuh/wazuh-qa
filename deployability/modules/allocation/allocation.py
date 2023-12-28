
from pathlib import Path
from pydantic import BaseModel
import yaml

from .providers import VagrantProvider, AmazonEC2Provider, Provider
from .providers.instances.generic import Instance
from .providers.generic import InstanceParams
from .models import InputPayload, InventoryOutput, TrackOutput

PROVIDERS = {'vagrant': VagrantProvider, 'aws': AmazonEC2Provider}


class Allocation:
    @classmethod
    def create(cls, base_dir: str | Path, payload: InputPayload, credentials: dict = None) -> tuple[str, str]:
        payload = InputPayload(**dict(payload))
        provider: Provider = PROVIDERS[payload.provider]()
        instance_params = InstanceParams(**dict(payload))
        instance = provider.create_instance(base_dir, instance_params, credentials)
        # Set the output files if they are not set.
        if not payload.inventory_output:
            payload.inventory_output = Path(base_dir, 'inventory.yml')
        if not payload.track_output:
            payload.track_output = Path(base_dir, 'track.yml')
        cls.__generate_inventory(instance, payload.inventory_output)
        cls.__generate_track_file(instance, payload.provider, payload.track_output)
        return payload.inventory_output, payload.track_output

    @staticmethod
    def __generate_inventory(instance: Instance, inventory_path: Path) -> None:
        inventory_path = Path(inventory_path)
        ssh_config = instance.ssh_connection_info()
        inventory = InventoryOutput(ansible_host=ssh_config.hostname,
                                    ansible_user=ssh_config.user,
                                    ansible_port=ssh_config.port,
                                    ansible_ssh_private_key_file=ssh_config.private_key)
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory.model_dump(), f)

    @staticmethod
    def __generate_track_file(instance: Instance, provider_name: str,  track_path: Path) -> None:
        track_path = Path(track_path)
        track = TrackOutput(identifier=instance.identifier,
                            provider=provider_name,
                            instance_dir=str(instance.path),
                            key_path=str(instance.credentials.key_path))
        with open(track_path, 'w') as f:
            yaml.dump(track.model_dump(), f)
        
    # def destroy(self, )