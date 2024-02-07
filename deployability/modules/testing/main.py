import argparse
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(project_root)

from modules.testing import Tester, InputPayload

def parse_arguments():
    parser = argparse.ArgumentParser(description="Wazuh testing tool")
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--tests", required=True)
    parser.add_argument("--component", choices=['manager', 'agent'], required=True)
    parser.add_argument("--dependencies", required=False)
    parser.add_argument("--cleanup", required=False, default=True)
    parser.add_argument("--wazuh-version", required=True)
    parser.add_argument("--wazuh-revision", required=True)
    parser.add_argument("--wazuh-branch", required=False)
    return parser.parse_args()

if __name__ == "__main__":
    Tester.run(InputPayload(**vars(parse_arguments())))



# linux-ubuntu-20.04-amd64:                                   
#   hosts:
#     VAGRANT-F6FD6643-B41E-4112-A652-3CFF8CC26F51:
#       ansible_host: 127.0.0.1
#       ansible_port: 2222
#       ansible_ssh_private_key_file: C:\tmp\wazuh-qa\VAGRANT-F6FD6643-B41E-4112-A652-3CFF8CC26F51\instance_key        
#       ansible_user: vagrant