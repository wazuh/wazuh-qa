from aws import AWSInfra
from vagrant import VagrantProvider
import uuid


class ProviderFactory():

    @staticmethod
    def create(infra_config : dict, base_dir):
        print(f"Creating {infra_config['composite-name']} infrastructure")
        if infra_config['provider'] == 'aws':
            provider = AWSInfra()
        elif infra_config['provider'] == 'vagrant':
            provider = VagrantProvider()
        else:
            raise Exception('Invalid provider: {}'.format(infra_config['provider']))
        provider.init(infra_config, base_dir, uuid.uuid4().hex)
        return provider

    @staticmethod
    def load_from_db(inventory_db_entry: dict, base_dir: str):
        if inventory_db_entry['instance_params']['provider'] == 'aws':
            provider = AWSInfra()
        elif inventory_db_entry['instance_params']['provider'] == 'vagrant':
            provider = VagrantProvider()
        else:
            raise Exception('Invalid provider: {}'.format(inventory_db_entry['instance_params']))
        provider.from_db(inventory_db_entry, base_dir)
        return provider
