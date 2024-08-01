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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

import os
import shutil
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509 import CertificateBuilder, Name, NameOID, random_serial_number
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from cryptography.x509 import CertificateBuilder, Name, NameAttribute, random_serial_number

current_file_path = os.path.abspath(__file__)


@contextmanager
def change_dir(new_path):
    original_path = Path.cwd()
    os.chdir(new_path)
    try:
        yield
    finally:
        os.chdir(original_path)


def run_service(service_name, port, database_path, certs_path):
    project_path = Path(__file__).resolve().parent.parent / 'manager_services' / service_name
    cert_path = os.path.join(certs_path, 'cert.pem')
    key_path = os.path.join(certs_path, 'private_key.pem')

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
        print(f"Starting {service_name} on port {port}...")
        return subprocess.Popen(command)

def create_manager_database(server_path):
    database_path = os.path.join(server_path, 'agents.db')
    if os.path.exists(database_path):
        logging.info("Detected existing database. Removing")
        os.remove(database_path)

    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY,
            uuid TEXT NOT NULL,
            credential TEXT NOT NULL,
            name TEXT
        )
    ''')
    conn.commit()
    conn.close()

    return database_path


def create_manager_credentials(server_path):
    # Generate a private key for use with ECDSA
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate the public key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # Define certificate details
    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        NameAttribute(NameOID.ORGANIZATION_NAME, u"Wazuh"),
        NameAttribute(NameOID.COMMON_NAME, u"wazuh.com"),
    ])

    # Create a self-signed certificate
    cert = CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=public_key,
        serial_number=random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365),  # 1 year validity
    ).sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )

    # Serialize certificate to PEM format
    cert_pem = cert.public_bytes(encoding=Encoding.PEM)

    # Create the credentials directory if it doesn't exist
    credentials_path = os.path.join(server_path, 'certs')

    if os.path.exists(credentials_path):
        logging.info("Detected existing certs. Removing")
        shutil.rmtree(credentials_path)

    os.mkdir(credentials_path)

    # Save keys and certificate to files
    with open(os.path.join(credentials_path, 'private_key.pem'), 'wb') as private_file:
        private_file.write(private_pem)

    with open(os.path.join(credentials_path, 'public_key.pem'), 'wb') as public_file:
        public_file.write(public_pem)

    with open(os.path.join(credentials_path, 'cert.pem'), 'wb') as cert_file:
        cert_file.write(cert_pem)

    logging.info(f"Credentials and certificate saved to {credentials_path}")

    return credentials_path


def main():
    """Main function to run both services."""

    arguments = parse_parameters()

    server_path = arguments.server_path
    if not arguments.server_path:
        logging.info("Creating server directory")
        server_path = tempfile.mkdtemp()
        logging.info(server_path)

    database_path = create_manager_database(server_path)
    certs_path = create_manager_credentials(server_path)

    services = {
        "agent_comm_mock": arguments.agent_comm_api_port,
        "manager_server_mock": arguments.manager_api_port
    }

    processes = []
    for service, port in services.items():
        proc = run_service(service, port, database_path, certs_path)
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
                            default='', help='Server files path', dest='server_path')

    arg_parser.add_argument('--debug',
                            help='Enable debug mode',
                            required=False,
                            action='store_true',
                            default=False,
                            dest='debug')



    return arg_parser.parse_args()

if __name__ == "__main__":
    main()
