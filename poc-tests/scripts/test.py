import argparse
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from src.classes import Ansible
import provision as provisioner


def main(version: str,
         revision: str,
         live: bool = True,
         inventory: str = None,
         provision: bool = False,
         tinybird_token: str = '',
         tinybird_datasource: str = '',
         tinybird_url: str = ''
         ):

    if not inventory:
        inventory = "inventory.yaml"

    if provision:
        provisioner.main(inventory)

    playbook_path = f"{project_root}/playbooks"

    test_playbooks = [
        "tests/test_repo.yml",
        "tests/test_install.yml",
        "tests/test_registration.yml",
        "tests/test_connection.yml",
        "tests/test_basic_info.yml",
        "tests/test_restart.yml",
        "tests/test_stop.yml",
        "tests/test_uninstall.yml"
    ]

    # Tiny bird

    if live:
        branch_version = "v" + version

    extra_vars = {
        'version': version,
        'revision': revision,
        'branch_version': branch_version,
        'tinybird_token': tinybird_token,
        'tinybird_datasource': tinybird_datasource,
        'tinybird_url': tinybird_url
    }

    ansible = Ansible(inventory, playbook_path)

    ansible.run_playbook('tests/provision.yml')

    for playbook in test_playbooks:
        ansible.run_playbook(playbook, extra_vars)

    ansible.run_playbook('clear.yml')


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", help="Wazuh version.")
    parser.add_argument("-r", "--revision", help="Wazuh revision.")
    parser.add_argument("-l", "--is_live", default=True, help="Wazuh version is live or not.")
    parser.add_argument("-i", "--inventory", default=None, help="Archivo YAML de inventario de Ansible.")
    parser.add_argument("-p", "--provision", default=False, help="Bool que indica si los sistemas se necesitan provisionar.")
    parser.add_argument("-tt", "--tinybird_token", default="", help="TinyBird token to connect with.")
    parser.add_argument("-td", "--tinybird_datasource", default="test", help="TinyBird datasource to send the results to.")
    parser.add_argument("-tu", "--tinybird_url", default="https://api.us-east.tinybird.co", help="TinyBird region url.")

    args = parser.parse_args()

    main(args.version, args.revision, args.is_live, args.inventory, args.provision,
         args.tinybird_token, args.tinybird_datasource, args.tinybird_url)

    # live = True
    # version = '4.7.0'
    # revision = '40704'