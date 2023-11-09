import argparse
import subprocess
import os
import sys

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

def install_dependencies():
  venv_path = 'venv'
  if not os.path.exists(venv_path):
      subprocess.run(['python3', '-m', 'venv', venv_path], check=True)
  activate_script = os.path.join(venv_path, 'bin', 'activate')
  activate_command = f"source {activate_script}" if sys.platform != 'win32' else f"call {activate_script}"
  subprocess.run(activate_command, shell=True)
  subprocess.run(['python3', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
  subprocess.run(['pip', 'install', '-r', 'requirements.txt'], check=True)


# ----------------------------------------------

def main(inventory_file):

  install_dependencies()

  project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
  sys.path.append(project_root)

  import src.classes.Ansible as Ansible

  ansible = Ansible.Ansible(inventory_file)
  inventory = Ansible.get_inventory(ansible, inventory)

  run(ansible, inventory)

# ---------------- Main ---------------------

if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--inventory", help="Archivo YAML de inventario de Ansible")
  args = parser.parse_args()

  main(args.inventory)