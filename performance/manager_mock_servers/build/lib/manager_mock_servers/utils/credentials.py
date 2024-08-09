# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""This module provides utilities for generating and managing elliptic curve cryptographic keys and X.509 certificates.

Functions:
- `create_private_key()`: Generates an EC (Elliptic Curve) private key using the SECP256R1 curve.
- `create_public_key(private_key)`: Derives the corresponding EC public key from a given private key.
- `create_certificate(public_key, private_key, country='US', province='California', locality='San Francisco', org='Wazuh', commom_name='wazuh.com')`: Creates a self-signed X.509 certificate using the provided public and private keys.
- `write_private_key(private_key, credentials_path, private_key_pem_name='private_key.pem')`: Serializes the EC private key and writes it to a PEM file.
- `write_public_key(public_key, credentials_path, public_key_pem_name='public_key.pem')`: Serializes the EC public key and writes it to a PEM file.
- `write_certificate(cert, credentials_path)`: Serializes the X.509 certificate and writes it to a PEM file.
- `create_manager_credentials(credentials_path)`: Generates a private key, public key, and self-signed certificate, and writes them to the specified directory.
"""
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
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, random_serial_number, Certificate
from datetime import datetime, timedelta
import os
import logging
import shutil


def create_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a new EC (Elliptic Curve) private key using the SECP256R1 curve.

    Returns:
        ec.EllipticCurvePrivateKey: The generated private key.
    """
    return ec.generate_private_key(ec.SECP256R1())

def create_public_key(private_key: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePublicKey:
    """Generate the public key corresponding to the provided EC private key.

    Args:
        private_key (ec.EllipticCurvePrivateKey): The EC private key from which to derive the public key.

    Returns:
        ec.EllipticCurvePublicKey: The derived public key.
    """
    return private_key.public_key()

def create_certificate(public_key: ec.EllipticCurvePublicKey, private_key: ec.EllipticCurvePrivateKey, country: str='US', province: str='California', locality: str='San Francisco', org: str='Wazuh',
                       commom_name: str='wazuh.com') -> Certificate:
    """Create a self-signed X.509 certificate using the provided public and private keys.

    Args:
        public_key (ec.EllipticCurvePublicKey): The public key to include in the certificate.
        private_key (ec.EllipticCurvePrivateKey): The private key used to sign the certificate.
        country (str): The country name for the certificate subject (default is 'US').
        province (str): The state or province name for the certificate subject (default is 'California').
        locality (str): The locality name for the certificate subject (default is 'San Francisco').
        org (str): The organization name for the certificate subject (default is 'Wazuh').
        commom_name (str): The common name for the certificate subject (default is 'wazuh.com').

    Returns:
        x509.Certificate: The created self-signed certificate.
    """
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

def write_private_key(private_key: ec.EllipticCurvePrivateKey, credentials_path: str, private_key_pem_name: str='private_key.pem') -> None:
    """Write the provided EC private key to a PEM file.

    Args:
        private_key (ec.EllipticCurvePrivateKey): The private key to serialize and write.
        credentials_path (str): The directory path where the PEM file will be saved.
        private_key_pem_name (str): The name of the PEM file for the private key (default is 'private_key.pem').

    Returns:
        None
    """
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    with open(os.path.join(credentials_path, private_key_pem_name), 'wb') as private_file:
        private_file.write(private_pem)


def write_public_key(public_key: ec.EllipticCurvePublicKey, credentials_path: str, private_key_pem_name: str='public_key.pem') -> None:
    """Write the provided EC public key to a PEM file.

    Args:
        public_key (ec.EllipticCurvePublicKey): The public key to serialize and write.
        credentials_path (str): The directory path where the PEM file will be saved.
        public_key_pem_name (str): The name of the PEM file for the public key (default is 'public_key.pem').

    Returns:
        None
    """
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    with open(os.path.join(credentials_path, 'public_key.pem'), 'wb') as public_file:
        public_file.write(public_pem)

def write_certificate(cert: Certificate, credentials_path: str) -> None:
    """Write the provided X.509 certificate to a PEM file.

    Args:
        cert (x509.Certificate): The certificate to serialize and write.
        credentials_path (str): The directory path where the PEM file will be saved.

    Returns:
        None
    """
    # Serialize certificate to PEM format
    cert_pem = cert.public_bytes(encoding=Encoding.PEM)
    with open(os.path.join(credentials_path, 'cert.pem'), 'wb') as cert_file:
        cert_file.write(cert_pem)


def create_manager_credentials(credentials_path: str) -> None:
    """Generate a set of manager credentials including a private key, public key, and a self-signed certificate,
    and write them to specified files.

    Args:
        credentials_path (str): The directory path where the credentials files will be saved.

    Returns:
        None
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)


    # Save keys and certificate to files
    write_private_key(private_key, credentials_path)
    write_public_key(public_key, credentials_path)
    write_certificate(cert, credentials_path)
