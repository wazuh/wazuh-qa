import argparse
import os
import yaml
from wazuh_testing.qa_ctl.provisioning.QAProvisioning import QAProvisioning

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    yaml_config = {}
    instance_handler = None

    parser.add_argument('--config', '-c', type=str, action='store', required=True,
                        help='Path to the configuration file.')

    arguments = parser.parse_args()

    assert os.path.exists(arguments.config), f"{arguments.config} file doesn't exists"

    with open(arguments.config) as config_file_fd:
        yaml_config = yaml.safe_load(config_file_fd)

        qa_provisioning = QAProvisioning(yaml_config)
        qa_provisioning.process_inventory_data()
        qa_provisioning.process_deployment_data()
