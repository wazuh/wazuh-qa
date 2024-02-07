import argparse
import os
import sys
import ast
import json

# ---------------- Vars ------------------------

from modules.provision import Provision, models

# ---------------- Methods ---------------------


def parse_arguments():
  parser = argparse.ArgumentParser(description="Provision infraestructure tool")
  parser.add_argument("--inventory-agent", default=None, help="Inventory with agent host information")
  parser.add_argument("--inventory-manager", default=None, help="Inventory with manager host information")
  parser.add_argument('--install',  action='append', default=[], help='List of dictionaries for installation.')
  parser.add_argument('--uninstall',  action='append', default=[], help='List of dictionaries for uninstall.')
  return parser.parse_args()

if __name__ == "__main__":
  provision = Provision(models.InputPayload(**vars(parse_arguments())))
  provision.run()

# ----------------------------------------------
