import boto3
import yaml

class Utils:
    
    @staticmethod
    def extract_ansible_host(file_path):
        with open(file_path, 'r') as yaml_file:
            inventory_data = yaml.safe_load(yaml_file)
        return inventory_data.get('ansible_host')
