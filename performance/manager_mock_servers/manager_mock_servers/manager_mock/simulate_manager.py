import subprocess
import os
import sys
import argparse

from pathlib import Path
from contextlib import contextmanager
import tempfile
import logging
import sqlite3
import shutil

import time
import os
import shutil
import logging
from manager_mock_servers.utils.credentials import create_manager_credentials
import signal

current_file_path = os.path.abspath(__file__)


@contextmanager
def change_dir(new_path):
    original_path = Path.cwd()
    os.chdir(new_path)
    try:
        yield
    finally:
        os.chdir(original_path)


def run_service(service_name, port, database_path, certs_path, report_path):
    project_path = Path(__file__).resolve().parent.parent / 'manager_services' / service_name
    cert_path = os.path.join(certs_path, 'cert.pem')
    key_path = os.path.join(certs_path, 'private_key.pem')

    print(cert_path)
    print(key_path)

    with change_dir(project_path):
        command = [
            sys.executable,
            f"{service_name}.py",
            "--port", str(port),
            f"--database-path",
            database_path,
            "--key",
            key_path,
            "--cert",
            cert_path
        ]
        if service_name == 'agent_comm_mock':
            command.extend(['--report-path', report_path])


        print(f"Starting {service_name} on port {port}...")
        return subprocess.Popen(command, preexec_fn=preexec_function)

def preexec_function():
    # Set the child process to receive a SIGKILL when the parent dies
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    PR_SET_PDEATHSIG = 1
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)


def generate_certificates(server_path):
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
    """Main function to run both services."""

    arguments = parse_parameters()

    server_path = arguments.server_path
    credentials_path = generate_certificates(server_path)

    services = {
        "agent_comm_mock": arguments.agent_comm_api_port,
        "manager_server_mock": arguments.manager_api_port
    }

    processes = []
    for service, port in services.items():
        proc = run_service(service, port, arguments.server_path, credentials_path, arguments.report_path)
        processes.append(proc)

    try:
        for proc in processes:
            proc.wait()
    except KeyboardInterrupt:
        print("Terminating services...")
        for proc in processes:
            proc.terminate()
        for proc in processes:
            proc.wait()

def parse_parameters():
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
