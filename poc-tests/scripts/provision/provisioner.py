import sys
import os
import argparse
import subprocess

try:
  import poetry
except ImportError:
  subprocess.check_call(['curl -sSL https://install.python-poetry.org | python3 -'])
else:
  import poetry
  poetry.core.menv.install()

  import poetry.plugins
  poetry.plugins.activate('myplugin')

# Obtén la ruta al directorio raíz del proyecto 'poc-test'
#project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# Agrega la ruta del directorio raíz al PYTHONPATH
#sys.path.append(project_root)

import src.classes.Ansible as Ansible

def main(inventory_file):

  ansible = Ansible.Ansible(inventory_file)

  inventory = Ansible.get_inventory()

  for host in inventory['all']['hosts']:

    packages = inventory['all']['hosts'][host].get('install')
    remote_user = inventory['all']['hosts'][host].get('ansible_user')
    private_key = inventory['all']['hosts'][host].get('ansible_ssh_private_key_file')
    remote_port = inventory['all']['hosts'][host].get('ansible_port')

    if host == 'debian':
      pkg_manager = 'apt'
    elif host == 'alpine':
      pkg_manager = 'apk'
    else:
      pkg_manager = 'apt'

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
          pkg_manager: {
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