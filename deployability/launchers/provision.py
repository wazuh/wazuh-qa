# Python
import argparse
import os
import sys

# ---------------- Vars ------------------------

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from modules.provision import Provision, models

# ---------------- Methods ---------------------

def parse_arguments():
  parser = argparse.ArgumentParser(description="Provision infraestructure tool")
  parser.add_argument("--inventory-agent", required=False, help="Inventory with agent host information")
  parser.add_argument("--inventory-manager", required=False, help="Inventory with manager host information")
  parser.add_argument("--install", type=str, required=False, help='Componentes to be installed')
  parser.add_argument("--custom-credentials", required=False, default=None)
  return parser.parse_args()

if __name__ == "__main__":
  provision = Provision(models.InputPayload(**vars(parse_arguments())))
  provision.run()

# ----------------------------------------------
