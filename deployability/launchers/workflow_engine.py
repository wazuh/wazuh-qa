# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import argparse
import logging
import colorlog

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from modules.workflow_engine.workflow_processor import WorkflowProcessor
from modules.workflow_engine.models import InputPayload


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Execute tasks in a workflow.')
    parser.add_argument('workflow_file', type=str,help='Path to the workflow file (YAML format).')
    parser.add_argument('--threads', type=int, default=1, required=False, help='Number of threads to use for parallel execution.')
    parser.add_argument('--dry-run', action='store_true', required=False, help='Display the plan without executing tasks.')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO',
                        help='Log level.')
    parser.add_argument('--schema_file', required=False, type=str, help='Path to the schema file (YAML format)')
    return parser.parse_args()


def setup_logger(log_level: str) -> None:
    """Setup logger."""
    logger = logging.getLogger()
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(colorlog.ColoredFormatter("%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(console_handler)
    logger.setLevel(log_level)


def main() -> None:
    """Main entry point."""

    args = parse_arguments()
    setup_logger(args.log_level)
    processor = WorkflowProcessor(**dict(InputPayload(**vars(parse_arguments()))))
    processor.run()


if __name__ == "__main__":
    main()
