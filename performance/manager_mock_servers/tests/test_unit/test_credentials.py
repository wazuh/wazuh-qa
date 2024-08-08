# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Tests for credentials module."""
import os

from _pytest.tmpdir import TempPathFactory
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from manager_mock_servers.utils.credentials import (
    create_certificate,
    create_manager_credentials,
    create_private_key,
    create_public_key,
    write_certificate,
    write_private_key,
    write_public_key,
)


def test_create_private_key():
    """Test the `create_private_key` function.

    This test verifies that the `create_private_key()` function creates
    an instance of `ec.EllipticCurvePrivateKey`.

    It does this by calling the function and asserting that the returned
    object is of the expected type.

    Assertions:
        Asserts private_key is an instance of ec.EllipticCurvePrivateKey
    """
    private_key = create_private_key()
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)


def test_create_public_key():
    """Test the `create_public_key` function.

    This test verifies that the `create_public_key()` function creates
    an instance of `ec.EllipticCurvePublicKey` when given a private key.

    It does this by calling the function with a generated private key
    and asserting that the returned object is of the expected type.

    Assertions:
        Asserts public_key is an instance of ec.EllipticCurvePublicKey
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

    Assertions:
        Asserts cert is an instance of Certificate
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)
    assert isinstance(cert, Certificate)


def test_write_private_key(tmp_path_factory: TempPathFactory):
    """Test the `write_private_key` function.

    This test verifies that the `write_private_key()` function writes
    a private key to the specified directory and creates the expected
    file.

    It uses a temporary directory to ensure that the file is created
    correctly and asserts that the file exists at the expected location.

    Args:
        tmp_path_factory (TempPathFactory): A temporary directory factory.

    Assertions:
        Asserts private_key is correctly created and placed in the provided file.
    """
    private_key = create_private_key()
    temporal_dir = tmp_path_factory.mktemp('certs')

    private_key_path = os.path.join(temporal_dir, 'private_key.pem')
    write_private_key(private_key, str(temporal_dir))

    assert os.path.isfile(private_key_path)


def test_write_public_key(tmp_path_factory: TempPathFactory):
    """Test the `write_public_key` function.

    This test verifies that the `write_public_key()` function writes
    a public key to the specified directory and creates the expected
    file.

    It uses a temporary directory to ensure that the file is created
    correctly and asserts that the file exists at the expected location.

    Args:
        tmp_path_factory (TempPathFactory): A temporary directory factory.

    Assertions:
        Asserts public_key is correctly created and placed in the provided file.
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)

    temporal_dir = tmp_path_factory.mktemp('certs')
    public_key_path = os.path.join(temporal_dir, 'public_key.pem')

    write_public_key(public_key, str(temporal_dir))

    assert os.path.isfile(public_key_path)


def test_write_certificate(tmp_path_factory: TempPathFactory):
    """Test the `write_certificate` function.

    This test verifies that the `write_certificate()` function writes
    a certificate to the specified directory and creates the expected
    file.

    It uses a temporary directory to ensure that the file is created
    correctly and asserts that the file exists at the expected location.

    Args:
        tmp_path_factory (TempPathFactory): A temporary directory factory.

    Assertions:
        Asserts certificate is correctly created and placed in the provided file.
    """
    private_key = create_private_key()
    public_key = create_public_key(private_key)
    cert = create_certificate(public_key, private_key)

    credentials_path = tmp_path_factory.mktemp('certs')
    cert_path = os.path.join(credentials_path, 'cert.pem')

    write_certificate(cert, str(credentials_path))

    assert os.path.isfile(cert_path)


def test_create_manager_credentials(tmp_path_factory: TempPathFactory):
    """Test the `create_manager_credentials` function.

    This test verifies that the `create_manager_credentials()` function
    creates all necessary credential files (private key, public key, and
    certificate) in the specified directory.

    It uses a temporary directory to ensure that all files are created
    correctly and asserts that each expected file exists at the correct
    location.

    Args:
        tmp_path_factory (TempPathFactory): A temporary directory factory.

    Assertions:
        Asserts certificate, private and public keys are correctly created.
    """
    credentials_path = tmp_path_factory.mktemp('credentials')

    create_manager_credentials(str(credentials_path))

    private_key_path = os.path.join(credentials_path, 'private_key.pem')
    public_key_path = os.path.join(credentials_path, 'public_key.pem')
    cert_path = os.path.join(credentials_path, 'cert.pem')

    assert os.path.isfile(private_key_path)
    assert os.path.isfile(public_key_path)
    assert os.path.isfile(cert_path)
