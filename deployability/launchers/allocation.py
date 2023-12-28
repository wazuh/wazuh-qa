import argparse
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from modules.generic.parser import pydantic_argument_parser
from modules.allocation.providers import instances, credentials, vagrant
from modules.allocation import Allocation



print(    "In module products sys.path[0], __package__ ==", sys.path[0], __package__)


# def parse_arguments():
#     parser = argparse.ArgumentParser(
#         description="Infrastructure providing tool")
#     parser.add_argument("--working-dir", required=False, default=Path('/tmp/wazuh-infra'),
#                         dest='working_dir', help='Working directory to store the infrastructure files')
#     # subparsers = parser.add_subparsers(dest='command', required=True, help='Action to perform')
#     # create = subparsers.add_parser('create', help='Create a new infrastructure')
#     # create.add_argument('--input', required=True, dest='create_input', help='Input file to create')
#     # create.add_argument('--inventory-output', required=False, dest='inventory_file', help='Output file to store the inventory')
#     # subparsers.add_parser('delete', help='Delete an existing infrastructure')
#     # subparsers.add_parser('status', help='Show the status of an existing infrastructure')
#     return parser.parse_args()


def main():
    # parser = pydantic_argument_parser(,InputPayload)
    
    Allocation.create('/tmp/wazuh-infra', {'provider': 'vagrant',
                                           'size': 'medium','composite_name': 'linux-ubuntu-22.04-amd64'})


if __name__ == "__main__":
    main()
