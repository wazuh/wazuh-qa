from aws import AWSInfra
from vagrant import VagrantInfra
import uuid


class ProviderFactory():

    @staticmethod
    def create(infra_config : dict, working_dir):
        print(f"Creating {infra_config['composite-name']} infrastructure")
        if infra_config['provider'] == 'aws':
            provider = AWSInfra()
        elif infra_config['provider'] == 'vagrant':
            provider = VagrantInfra()
        else:
            raise Exception('Invalid provider: {}'.format(infra_config['provider']))
        provider.init(infra_config, working_dir, uuid.uuid4().hex)
        return provider

    @staticmethod
    def load_from_db(inventory_db_entry: dict, working_dir: str):
        if inventory_db_entry['instance_params']['provider'] == 'aws':
            provider = AWSInfra()
        elif inventory_db_entry['instance_params']['provider'] == 'vagrant':
            provider = VagrantInfra()
        else:
            raise Exception('Invalid provider: {}'.format(inventory_db_entry['instance_params']))
        provider.from_db(inventory_db_entry, working_dir)
        return provider
