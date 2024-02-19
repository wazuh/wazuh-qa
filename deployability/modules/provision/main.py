import argparse
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(project_root)

from modules.provision import Provision, models

# ---------------- Methods ---------------------


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Provision infraestructure tool")
    parser.add_argument("--inventory-agent", default=None, help="Inventory with agent host information")
    parser.add_argument("--inventory-manager", default=None, help="Inventory with manager host information")
    parser.add_argument('--install',  action='append', default=[], help='List of dictionaries for installation.')
    parser.add_argument('--uninstall',  action='append', default=[], help='List of dictionaries for uninstall.')
    return parser.parse_args()


if __name__ == "__main__":
    try:
        provision = Provision(models.InputPayload(**vars(parse_arguments())))
        provision.run()
    except Exception as e:
        sys.exit(f"Error while provisioning: {e}")
