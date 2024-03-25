import argparse
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(project_root)

from modules.testing import Tester, InputPayload


def parse_arguments():
    parser = argparse.ArgumentParser(description="Wazuh testing tool")
    parser.add_argument("--targets", action='append', default=[], required=True)
    parser.add_argument("--tests", required=True)
    parser.add_argument("--component", choices=['manager', 'agent'], required=True)
    parser.add_argument("--dependencies", action='append', default=[], required=False)
    parser.add_argument("--cleanup", required=False, default=True)
    parser.add_argument("--wazuh-version", required=True)
    parser.add_argument("--wazuh-revision", required=True)
    parser.add_argument("--wazuh-branch", required=False)
    parser.add_argument("--live", required=False)

    return parser.parse_args()

if __name__ == "__main__":
    Tester.run(InputPayload(**vars(parse_arguments())))
