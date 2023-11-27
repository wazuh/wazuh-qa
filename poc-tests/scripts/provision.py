# Python
import argparse
import subprocess
import os
import sys

# ---------------- Vars ------------------------

CURRENT_DIR = os.path.abspath(os.getcwd())
SUMMARY = {}

# ---------------- Methods ---------------------

def main(inventory_file):

  install_dependencies()

  project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
  sys.path.append(project_root)

  from src.classes import Ansible, Provision

  ansible = Ansible(inventory_file)
  provision = Provision(ansible)

  run(provision)

# ----------------------------------------------

def run(provision):
    inventory = provision.get_inventory()
    provision.set_directory(CURRENT_DIR)

    for host, host_info in inventory['all']['hosts'].items():
      install_host_dependencies(host, host_info, provision)

      components = host_info.get('install', [])

      for item in components:
        component, install_type, version = (item.get('component'), item.get('type'), item.get('version')) if isinstance(item, dict) else (item, None, None)

        install_info = {
          'component': component,
          'install_type': install_type,
          'version': version
        }

        status = provision.handle_package(host, host_info, install_info)

        update_status(status)

    print("summary")
    print(SUMMARY)

# ----------------------------------------------

def install_dependencies():
  #try:
  #    subprocess.check_call(["apt-get", "install", "pip", "python3.10-venv", "-y"])
  #except subprocess.CalledProcessError:
  #    print(f"Package pip already installed")
  venv_path = 'venv'
  if not os.path.exists(venv_path):
      subprocess.run(['python3', '-m', 'venv', venv_path], check=True)
  activate_script = os.path.join(venv_path, 'bin', 'activate')
  activate_command = f"source {activate_script}" if sys.platform != 'win32' else f"call {activate_script}"
  subprocess.run(activate_command, shell=True)
  subprocess.run(['python3', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
  subprocess.run(['pip', 'install', '-r', 'utils/requirements.txt'], check=True)

# ----------------------------------------------

def install_host_dependencies(host, host_info, provision):
  task = ["dependencies.j2"]
  install_info = {
    'component': os.path.join(CURRENT_DIR, "utils", "remote_requirements.txt"),
    'install_type': "deps"
  }

  status = provision.install(host, host_info, install_info, task)

  update_status(status)

# ----------------------------------------------

def update_status(status):
    SUMMARY.update(status.stats)

# ---------------- Main ---------------------

if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--inventory", help="Archivo YAML de inventario de Ansible")
  args = parser.parse_args()

  main(args.inventory)