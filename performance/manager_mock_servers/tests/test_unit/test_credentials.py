import pytest
from unittest.mock import mock_open
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509 import Certificate

from manager_mock_servers.utils.credentials import (create_private_key, create_public_key, create_certificate,
                         write_private_key, write_public_key, write_certificate, create_manager_credentials)


def test_create_private_key():
    private_key = create_private_key()
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)

def test_create_public_key():
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)

def test_create_certificate():
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)
    assert isinstance(cert, Certificate)

def test_write_private_key(tmpdir):
    private_key = create_private_key()
    credentials_path = tmpdir.mkdir("credentials")
    write_private_key(private_key, credentials_path)

    private_key_path = credentials_path.join("private_key.pem")
    assert private_key_path.isfile()

def test_write_public_key(tmpdir):
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    credentials_path = tmpdir.mkdir("credentials")
    write_public_key(public_key, credentials_path)

    public_key_path = credentials_path.join("public_key.pem")
    assert public_key_path.isfile()

def test_write_certificate(tmpdir):
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)
    credentials_path = tmpdir.mkdir("credentials")
    write_certificate(cert, credentials_path)

    cert_path = credentials_path.join("cert.pem")
    assert cert_path.isfile()

def test_create_manager_credentials(tmpdir):
    credentials_path = tmpdir.mkdir("credentials")
    create_manager_credentials(credentials_path)

    private_key_path = credentials_path.join("private_key.pem")
    public_key_path = credentials_path.join("public_key.pem")
    cert_path = credentials_path.join("cert.pem")

    assert private_key_path.isfile()
    assert public_key_path.isfile()
    assert cert_path.isfile()
