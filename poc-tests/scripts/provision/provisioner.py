# provisioner.py

import src.classes.Ansible as Ansible
import yaml
import argparse

def main(inventory_file):

  ansible = Ansible.Ansible(inventory_file)

  inventory = Ansible.get_inventory()

  for host in inventory['all']['hosts']:

    packages = inventory['all']['hosts'][host].get('install')
    remote_user = inventory['all']['hosts'][host].get('ansible_user')
    private_key = inventory['all']['hosts'][host].get('ansible_ssh_private_key_file')
    remote_port = inventory['all']['hosts'][host].get('ansible_port')

    install_playbook = {
      'name': 'Install packages on '+host,
      'hosts': host,
      'remote_user': remote_user,
      'port': remote_port,
      'vars': {
        'ansible_ssh_private_key_file': private_key
      },
      'tasks': [
        {
          'apt': {
            'name': packages,
            'state': 'present'
            }
        }
      ]
    }

    results = ansible.run_playbook(install_playbook)
    print(results.stats)

# -------------------------------------
#   Main
# -------------------------------------

if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--inventory", help="Archivo YAML de inventario de Ansible")
  args = parser.parse_args()

  main(args.inventory)