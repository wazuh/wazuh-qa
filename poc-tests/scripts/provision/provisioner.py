import argparse
import subprocess
import os
import sys

# ---------------- Methods ---------------------

def run(ansible, inventory):
  for host in inventory['all']['hosts']:

    packages = inventory['all']['hosts'][host].get('install')
    distribution = inventory['all']['hosts'][host].get('distribution')
    remote_user = inventory['all']['hosts'][host].get('ansible_user')
    private_key = inventory['all']['hosts'][host].get('ansible_ssh_private_key_file')
    remote_port = inventory['all']['hosts'][host].get('ansible_port')

    for package in packages:
      install_playbook = {
        'name': 'Install packages on '+host,
        'hosts': host,
        'remote_user': remote_user,
        'port': remote_port,
        'vars': {
          'ansible_ssh_private_key_file': private_key
        },
        'tasks': []
      }

      tasks = getTask(package, distribution)

      install_playbook['tasks'].extend(tasks)

      results = ansible.run_playbook(install_playbook)
      print(results.stats)

# ----------------------------------------------

def getTask(package, distribution):
  tasks = []
  pkg_manager

  if distribution == 'debian':
    pkg_manager = 'apt'
  if distribution == 'rpm':
    pkg_manager = 'yum'

  if "wazuh" in package:
    if distribution == 'debian':
      tasks.extend([
        {
            'name': 'Install gnupg and apt-transport-https',
            'apt': {
                'name': 'gnupg,apt-transport-https',
                'state': 'present'
            }
        },
        {
            'name': 'Import GPG key',
            'command': 'curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg'
        },
        {
            'name': 'Add Wazuh repository',
            'lineinfile': {
                'dest': '/etc/apt/sources.list.d/wazuh.list',
                'line': 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main'
            }
        },
        {
            'name': 'Update packages information',
            'apt': {
                'update_cache': 'yes'
            }
        }
      ])
    if distribution == 'rpm':
      tasks.extend([
        {
            'name': 'Import GPG key',
            'command': 'rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH'
        },
        {
            'name': 'Add Wazuh repository',
            'copy': {
                'src': 'files/wazuh.repo',
                'dest': '/etc/yum.repos.d/wazuh.repo'
            }
        }
      ])

  tasks.extend([
    {
        'name': 'Install' + package,
        pkg_manager: {
            'name': package,
            'state': 'present'
        }
    }
  ])

  return tasks


# ----------------------------------------------

def install_dependencies():
  venv_path = 'venv'
  if not os.path.exists(venv_path):
      subprocess.run(['python3', '-m', 'venv', venv_path], check=True)
  activate_script = os.path.join(venv_path, 'bin', 'activate')
  activate_command = f"source {activate_script}" if sys.platform != 'win32' else f"call {activate_script}"
  subprocess.run(activate_command, shell=True)
  subprocess.run(['python3', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
  subprocess.run(['pip', 'install', '-r', 'utils/requirements.txt'], check=True)


# ----------------------------------------------

def main(inventory_file):

  install_dependencies()

  project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
  sys.path.append(project_root)

  import src.classes.Ansible as Ansible

  ansible = Ansible.Ansible(inventory_file)
  inventory = ansible.get_inventory()

  run(ansible, inventory)

# ---------------- Main ---------------------

if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--inventory", help="Archivo YAML de inventario de Ansible")
  args = parser.parse_args()

  main(args.inventory)