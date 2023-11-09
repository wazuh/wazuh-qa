import argparse
import subprocess
import json

try:
  import poetry
except ImportError:
  subprocess.check_call(['curl', '-sSL', 'https://install.python-poetry.org', '>', 'install.py'])
  subprocess.check_call(['python3', 'install.py'])
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

# ---------------- Methods ---------------------

def run(ansible, inventory):
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

# ----------------------------------------------

def provisionNode():

  if is_ansible_installed():
    result = subprocess.check_call(['cat /etc/os-release'])
    os_info = result.stdout.decode('utf-8').lower()

    if 'ubuntu' in os_info:
      subprocess.check_call(['sudo apt-get update && apt-get install -y ansible'])
    elif 'centos' in os_info:
      subprocess.check_call(['sudo yum -y install epel-release && yum -y install ansible'])
    elif 'debian' in os_info:
      subprocess.check_call(['sudo apt-get update && apt-get install -y ansible'])
    elif 'alpine' in os_info:
      subprocess.check_call(['sudo apk update && apk add ansible'])
    else:
      print("Unsupported operating system")

# ----------------------------------------------

def is_ansible_installed():
    try:
        subprocess.check_output(['ansible', '--version'], stderr=subprocess.STDOUT, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return False

# ----------------------------------------------

def main(inventory_file):

  provisionNode()

  ansible = Ansible.Ansible(inventory_file)
  inventory = Ansible.get_inventory(ansible, inventory)

  run(ansible, inventory)

# ---------------- Main ---------------------

if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--inventory", help="Archivo YAML de inventario de Ansible")
  args = parser.parse_args()

  main(args.inventory)