#!/home/fcaffieri/repos/wazuh-qa/.venv/bin/python3
import argparse
import logging
from workflow_processor import WorkflowProcessor
import sys, os

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Execute tasks in a workflow.')
    parser.add_argument('workflow_file', type=str, help='Path to the workflow file (YAML format).')
    parser.add_argument('schema_file', type=str, default="./schema.json", help='Path to the schema definition file.')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads to use for parallel execution.')
    parser.add_argument('--dry-run', action='store_true', help='Display the plan without executing tasks.')
    parser.add_argument('--log-format', choices=['plain', 'json'], default='plain', help='Log format (plain or json).')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO',
                        help='Log level.')
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_arguments()

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    print(project_root)
    sys.path.append(project_root)

    from src.classes import SchemaValidator

    validator = SchemaValidator(args.schema_file, args.workflow_file)
    validator.preprocess_data()
    validator.validateSchema()

    #processor = WorkflowProcessor(args.workflow_file, args.dry_run, args.threads)
    #processor.logger = processor.setup_logger(log_format=args.log_format, log_level=args.log_level)
    #processor.main()


if __name__ == "__main__":
    main()