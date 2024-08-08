"""This script is designed to manage and run mock server services for testing purposes.

It includes functionalities to start server and agent communication services, generate necessary SSL certificates,
and handle process management.

Functions:
- change_dir(new_path): A context manager that temporarily changes the current working directory to `new_path`
and reverts it back after the context ends.
- run_server_management(port, database_path, certs_path): Starts a mock server management service as a subprocess.
- run_agent_comm(port, database_path, certs_path, report_path): Starts a mock agent communication
service as a subprocess.
- preexec_function(): Configures the subprocess to receive a SIGKILL signal if the parent process dies.
- generate_certificates(server_path): Creates and returns the path to SSL certificates for server communication.
- main(): The main entry point of the script that parses arguments, sets up the server and agent services,
and manages their lifecycle.
- parse_parameters(): Parses command-line arguments and returns them as a namespace object.

Example:
    python script.py --manager-api-port 60000 --agent-comm-api-port 3000 --server-path /path/to/server \
    --report-path /path/to/report.csv
"""

import argparse
import ctypes
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from manager_mock_servers.utils.credentials import create_manager_credentials

current_file_path = os.path.abspath(__file__)


@contextmanager
def change_dir(new_path):
    """Context manager for temporarily changing the current working directory.

    Args:
        new_path (str or Path): The path to change the working directory to.

    Yields:
        None: Changes the directory and yields control to the block of code inside the `with` statement.

    Raises:
        OSError: If there is an error changing the directory.
    """
    original_path = Path.cwd()
    os.chdir(new_path)
    try:
        yield
    finally:
        os.chdir(original_path)


def run_server_management(port, database_path, certs_path):
    """Starts a mock server management service as a subprocess.

    Args:
        port (int): The port number on which the server will listen.
        database_path (str): Path to the database file.
        certs_path (str): Path to the directory containing SSL certificates.

    Returns:
        subprocess.Popen: The subprocess object representing the started server process.

    Raises:
        FileNotFoundError: If the script or certificates are not found.
    """
    service_name = 'manager_server_mock'
    service_path = Path(__file__).resolve().parent.parent / 'manager_services' / service_name / service_name
    cert_path = os.path.join(certs_path, 'cert.pem')
    key_path = os.path.join(certs_path, 'private_key.pem')

    command = [
        sys.executable,
        f"{service_path}.py",
        "--port", str(port),
        "--database-path",
        database_path,
        "--key",
        key_path,
        "--cert",
        cert_path
    ]

    logging.info(f"Starting {service_name} on port {port}...")
    return subprocess.Popen(command, preexec_fn=preexec_function)


def run_agent_comm(port, database_path, certs_path, report_path):
    """Starts a mock agent communication service as a subprocess.

    Args:
        port (int): The port number on which the agent communication service will listen.
        database_path (str): Path to the database file.
        certs_path (str): Path to the directory containing SSL certificates.
        report_path (str): Path to the CSV file where metrics will be reported.

    Returns:
        subprocess.Popen: The subprocess object representing the started agent communication process.

    Raises:
        FileNotFoundError: If the script or certificates are not found.
    """
    service_name = 'agent_comm_mock'
    service_path = Path(__file__).resolve().parent.parent / 'manager_services' / service_name / service_name
    cert_path = os.path.join(certs_path, 'cert.pem')
    key_path = os.path.join(certs_path, 'private_key.pem')

    command = [
        sys.executable,
        f"{service_path}.py",
        "--port", str(port),
        "--database-path",
        database_path,
        "--key",
        key_path,
        "--cert",
        cert_path,
        '--report-path',
        report_path
    ]

    logging.info(f"Starting {service_name} on port {port}...")
    return subprocess.Popen(command, preexec_fn=preexec_function)


def preexec_function():
    """Configures the child process to receive a SIGKILL signal if the parent process dies.

    This function is used as a `preexec_fn` argument in `subprocess.Popen` to ensure that the child process
    is terminated if the parent process is killed.

    Raises:
        OSError: If the `prctl` function call fails.
    """
    # Set the child process to receive a SIGKILL when the parent dies
    libc = ctypes.CDLL('libc.so.6')
    PR_SET_PDEATHSIG = 1
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)


def generate_certificates(server_path):
    """Creates and returns the path to SSL certificates for server communication.

    Args:
        server_path (str): Path where certificates will be created. If not provided, a temporary
        directory will be created.

    Returns:
        str: Path to the directory containing the generated SSL certificates.

    Raises:
        OSError: If there is an error creating directories or files.
    """
    if not server_path:
        logging.info("Creating server directory")
        server_path = tempfile.mkdtemp()
        logging.info(server_path)

    credentials_path = os.path.join(server_path, 'certs')
    if os.path.exists(credentials_path):
        logging.info("Detected existing certs. Removing")
        shutil.rmtree(credentials_path)

    os.mkdir(credentials_path)
    create_manager_credentials(credentials_path)

    return credentials_path


def main():
    """Main entry point of the script that initializes and manages the mock services.

    Parses command-line arguments, generates certificates, starts the server and agent communication services,
    and manages their lifecycle. Handles process termination on KeyboardInterrupt.

    Raises:
        SystemExit: If an unexpected error occurs during script execution.
    """
    arguments = parse_parameters()

    server_path = arguments.server_path
    credentials_path = generate_certificates(server_path)

    processes = []
    processes.append(run_server_management(arguments.manager_api_port, arguments.server_path,
                     credentials_path))
    time.sleep(3)
    processes.append(run_agent_comm(arguments.agent_comm_api_port, arguments.server_path, credentials_path,
                     arguments.report_path))

    try:
        for proc in processes:
            proc.wait()
    except KeyboardInterrupt:
        for proc in processes:
            proc.terminate()
        for proc in processes:
            proc.wait()


def parse_parameters():
    """Parses command-line arguments for configuring the mock services.

    Returns:
        argparse.Namespace: A namespace object containing the parsed arguments.

    Raises:
        SystemExit: If there is an error in argument parsing or validation.
    """
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('--manager-api-port', metavar='<manager_port_address>', type=str, required=False,
                            default='55000', help='Manager Port', dest='manager_api_port')

    arg_parser.add_argument('--agent-comm-api-port', metavar='<agent_comm_api_port>', type=str, required=False,
                            default='2900', help='Agent comm API Port', dest='agent_comm_api_port')

    arg_parser.add_argument('--server-path', metavar='<server_path>', type=str, required=False,
                            help='Server files path', dest='server_path')

    arg_parser.add_argument('--report-path', type=str, required=True, help='Metrics report CSV file path', dest="report_path")

    arg_parser.add_argument('--debug',
                            help='Enable debug mode',
                            required=False,
                            action='store_true',
                            default=False,
                            dest='debug')

    return arg_parser.parse_args()


if __name__ == "__main__":
    main()
