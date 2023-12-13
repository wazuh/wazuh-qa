# import argparse
# import os
# import yaml
# import providers.provider as provider

# WORKING_DIR = os.path.join('/tmp', 'wazuh-infra')
# INFRADB_FILE = 'infra.db'
# PROVIDERS = ['aws', 'vagrant']

# def parse_arguments():
#     parser = argparse.ArgumentParser(description="Infrastructure providing tool")
#     parser.add_argument("--working-dir", required=False, default=WORKING_DIR, dest='working_dir', help='Working directory to store the infrastructure files')
#     subparsers = parser.add_subparsers(dest='command', required=True, help='Action to perform')
#     create = subparsers.add_parser('create', help='Create a new infrastructure')
#     create.add_argument('--input', required=True, dest='create_input', help='Input file to create')
#     create.add_argument('--inventory-output', required=False, dest='inventory_file', help='Output file to store the inventory')
#     subparsers.add_parser('delete', help='Delete an existing infrastructure')
#     subparsers.add_parser('status', help='Show the status of an existing infrastructure')
#     args = parser.parse_args()
#     return args


# def validate_args(args):
#     if not os.path.exists(args.working_dir):
#         os.makedirs(args.working_dir)
#     infradb_path = os.path.join(args.working_dir, INFRADB_FILE)
#     if args.command == 'create' and os.path.exists(infradb_path):
#         raise Exception('An infrastructure already exists in the working directory. Please delete it before creating a new one.')
#     if (args.command == 'delete' or args.command == 'status') and not os.path.exists(infradb_path):
#         raise Exception('No infrastructure exists in the working directory.')


# def main():

#     args = parse_arguments()
#     validate_args(args)
#     if args.command == 'create':
#         ansible_hosts = { 'hosts' : {}}
#         inventory_db = {}
#         with open(args.create_input, 'r') as input_file:
#             infra_request = yaml.safe_load(input_file)
#         for resource in infra_request:
#             infra = provider.ProviderFactory().create(resource, args.working_dir)
#             infra.create()
#             infra.start()
#             ansible_hosts['hosts'].update(infra.ansible_inventory())
#             inventory_db.update(infra.dump())
#         if args.inventory_file:
#             ansible_vars = { 'vars' : {'ansible_ssh_common_args':'-o StrictHostKeyChecking=no'}}
#             for request in infra_request:
#                 if request['role'] == 'agent':
#                     ansible_hosts['hosts'][request['alias']]['manager_ip'] = ansible_hosts['hosts']['Manager']['ansible_host']
#             inventory = { 'all': { **ansible_hosts, **ansible_vars }}
#             with open(args.inventory_file, 'w') as inventory_file:
#                 yaml.dump(inventory, inventory_file)

#         with open(os.path.join(args.working_dir, INFRADB_FILE), 'w') as db_file:
#             yaml.dump(inventory_db, db_file)

#     elif args.command == 'delete':
#         with open(os.path.join(args.working_dir, INFRADB_FILE), 'r') as db_file:
#             inventory_db = yaml.safe_load(db_file)
#         for resource in inventory_db:
#             infra = provider.ProviderFactory().load_from_db(inventory_db[resource], args.working_dir)
#             infra.stop()
#             infra.delete()
#         os.remove(os.path.join(args.working_dir, INFRADB_FILE))
#     elif args.command == 'status':
#         with open(os.path.join(args.working_dir, INFRADB_FILE), 'r') as db_file:
#             inventory_db = yaml.safe_load(db_file)
#         for resource in inventory_db:
#             infra = provider.ProviderFactory().load_from_db(inventory_db[resource], args.working_dir)
#             infra.status()

import os
import sys


project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from src.modules.allocation import providers, credentials

def main():
    creds = credentials.VagrantCredential("/tmp", "test")
    test = creds.generate()
    print(test)
    creds.delete()


if __name__ == "__main__":
    main()
