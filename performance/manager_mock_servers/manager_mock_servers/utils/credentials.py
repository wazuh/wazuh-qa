from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509 import CertificateBuilder, Name, NameOID, random_serial_number
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, random_serial_number
from datetime import datetime, timedelta
import os
import logging
import shutil


def create_private_key():
    return ec.generate_private_key(ec.SECP256R1())

def create_public_key(private_key):
    return private_key.public_key()

def create_certificate(public_key, private_key, country='US', province='California', locality='San Francisco', org='Wazuh',
                       commom_name='wazuh.com'):
    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, country),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
        NameAttribute(NameOID.LOCALITY_NAME, locality),
        NameAttribute(NameOID.ORGANIZATION_NAME, org),
        NameAttribute(NameOID.COMMON_NAME, commom_name),
    ])
    # Create a self-signed certificate
    cert = CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=public_key,
        serial_number=random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365),
    ).sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )

    return cert

def write_private_key(private_key, credentials_path, private_key_pem_name='private_key.pem'):
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    with open(os.path.join(credentials_path, private_key_pem_name), 'wb') as private_file:
        private_file.write(private_pem)


def write_public_key(public_key, credentials_path, private_key_pem_name='public_key.pem'):
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    with open(os.path.join(credentials_path, 'public_key.pem'), 'wb') as public_file:
        public_file.write(public_pem)

def write_certificate(cert, credentials_path):
    # Serialize certificate to PEM format
    cert_pem = cert.public_bytes(encoding=Encoding.PEM)
    with open(os.path.join(credentials_path, 'cert.pem'), 'wb') as cert_file:
        cert_file.write(cert_pem)



def create_manager_credentials(credentials_path):
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)


    # Save keys and certificate to files
    write_private_key(private_key, credentials_path)
    write_public_key(public_key, credentials_path)
    write_certificate(cert, credentials_path)
