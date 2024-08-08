import pytest
from unittest.mock import mock_open
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509 import Certificate

from manager_mock_servers.utils.credentials import (create_private_key, create_public_key, create_certificate,
                         write_private_key, write_public_key, write_certificate, create_manager_credentials)


def test_create_private_key():
    """Test the `create_private_key` function.

    This test verifies that the `create_private_key()` function creates
    an instance of `ec.EllipticCurvePrivateKey`.

    It does this by calling the function and asserting that the returned
    object is of the expected type.
    """
    private_key = create_private_key()
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)

def test_create_public_key():
    """Test the `create_public_key` function.

    This test verifies that the `create_public_key()` function creates
    an instance of `ec.EllipticCurvePublicKey` when given a private key.

    It does this by calling the function with a generated private key
    and asserting that the returned object is of the expected type.
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)

def test_create_certificate():
    """Test the `create_certificate` function.

    This test verifies that the `create_certificate()` function creates
    a `cryptography.x509.Certificate` instance when provided with a public
    and private key.

    It does this by calling the function with generated public and private
    keys and asserting that the returned object is of the expected type.
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)
    assert isinstance(cert, Certificate)

def test_write_private_key(tmpdir):
    """Test the `write_private_key` function.

    This test verifies that the `write_private_key()` function writes
    a private key to the specified directory and creates the expected
    file.

    It uses a temporary directory to ensure that the file is created
    correctly and asserts that the file exists at the expected location.

    Args:
        tmpdir (py.path.local): A temporary directory provided by pytest.
    """
    private_key = create_private_key()
    credentials_path = tmpdir.mkdir("credentials")
    write_private_key(private_key, credentials_path)

    private_key_path = credentials_path.join("private_key.pem")
    assert private_key_path.isfile()

def test_write_public_key(tmpdir):
    """Test the `write_public_key` function.

    This test verifies that the `write_public_key()` function writes
    a public key to the specified directory and creates the expected
    file.

    It uses a temporary directory to ensure that the file is created
    correctly and asserts that the file exists at the expected location.

    Args:
        tmpdir (py.path.local): A temporary directory provided by pytest.
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    credentials_path = tmpdir.mkdir("credentials")
    write_public_key(public_key, credentials_path)

    public_key_path = credentials_path.join("public_key.pem")
    assert public_key_path.isfile()

def test_write_certificate(tmpdir):
    """Test the `write_certificate` function.

    This test verifies that the `write_certificate()` function writes
    a certificate to the specified directory and creates the expected
    file.

    It uses a temporary directory to ensure that the file is created
    correctly and asserts that the file exists at the expected location.

    Args:
        tmpdir (py.path.local): A temporary directory provided by pytest.
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)
    credentials_path = tmpdir.mkdir("credentials")
    write_certificate(cert, credentials_path)

    cert_path = credentials_path.join("cert.pem")
    assert cert_path.isfile()

def test_create_manager_credentials(tmpdir):
    """
    Test the `create_manager_credentials` function.

    This test verifies that the `create_manager_credentials()` function
    creates all necessary credential files (private key, public key, and
    certificate) in the specified directory.

    It uses a temporary directory to ensure that all files are created
    correctly and asserts that each expected file exists at the correct
    location.

    Args:
        tmpdir (py.path.local): A temporary directory provided by pytest.
    """
    credentials_path = tmpdir.mkdir("credentials")
    create_manager_credentials(credentials_path)

    private_key_path = credentials_path.join("private_key.pem")
    public_key_path = credentials_path.join("public_key.pem")
    cert_path = credentials_path.join("cert.pem")

    assert private_key_path.isfile()
    assert public_key_path.isfile()
    assert cert_path.isfile()
