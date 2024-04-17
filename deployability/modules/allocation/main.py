# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(project_root)

from modules.allocation import Allocator
from modules.allocation.generic.models import InputPayload

def parse_arguments():
    parser = argparse.ArgumentParser(description="Infrastructure providing tool")
    parser.add_argument("--provider", choices=['vagrant', 'aws', None], required=False,  default=None)
    parser.add_argument("--size", choices=['micro', 'small', 'medium', 'large', None], required=False, default=None)
    parser.add_argument("--composite-name", required=False, default=None)
    parser.add_argument("--action", choices=['create', 'delete'], required=False, default='create')
    parser.add_argument("--ssh-key", required=False, default=None)
    parser.add_argument("--custom-provider-config", required=False, default=None)
    parser.add_argument("--track-output", required=False, default=None)
    parser.add_argument("--inventory-output", required=False, default=None)
    parser.add_argument("--working-dir", required=False, default='/tmp/wazuh-qa')
    parser.add_argument("--label-issue", required=False, default=None)
    parser.add_argument("--label-team", required=False, default=None)
    parser.add_argument("--label-termination-date", required=False, default=None)
    parser.add_argument("--instance-name", required=False, default=None)
    parser.add_argument("--rollback", choices=['True', 'False'], required=False, default=True)
    return parser.parse_args()


def main():
    Allocator.run(InputPayload(**vars(parse_arguments())))


if __name__ == "__main__":
    main()
