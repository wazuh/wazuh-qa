# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
import argparse
import signal

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(project_root)

from jobflow.jobflow_processor import JobFlowProcessor
from jobflow.models import InputPayload


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Execute tasks in a JobFlow.')
    parser.add_argument('jobflow_file', type=str,help='Path to the workflow file (YAML format).')
    parser.add_argument('--threads', type=int, default=1, required=False, help='Number of threads to use for parallel execution.')
    parser.add_argument('--dry-run', action='store_true', required=False, help='Display the plan without executing tasks.')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO',
                        help='Log level.')
    parser.add_argument('--schema_file', required=False, type=str, help='Path to the schema file (YAML format)')
    return parser.parse_args()

def main() -> None:
    """Main entry point."""
    try:
        args = parse_arguments()
        processor = JobFlowProcessor(**dict(InputPayload(**vars(args))))
        signal.signal(signal.SIGINT, processor.handle_interrupt)
        processor.run()
    except Exception as e:
        sys.exit(f"Error executing workflow: {e}")

if __name__ == "__main__":
    main()
