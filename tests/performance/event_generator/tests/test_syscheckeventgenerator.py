# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the SyscheckEventGenerator class."""

import os
import pytest
from pathlib import Path
from event_generator import SyscheckEventGenerator


@pytest.fixture
def setup_syscheck_generator(tmp_path: Path) -> tuple:
    """
    Setup for SyscheckEventGenerator with a temporary directory.

    Args:
        tmp_path (LocalPath): Temporary directory provided by pytest.

    Returns:
        tuple: A tuple containing an instance of SyscheckEventGenerator and the path to the directory.
    """
    path = tmp_path
    generator = SyscheckEventGenerator(rate=1, path=str(path), operations=5)
    return generator, path


def test_file_operations(setup_syscheck_generator: tuple):
    """
    Test file operations (create, modify, delete) performed by SyscheckEventGenerator.

    Args:
        setup_syscheck_generator (fixture): Fixture that provides a SyscheckEventGenerator and a path.
    """
    generator, path = setup_syscheck_generator
    generator.start()
    # Since operations are random, we check if any file exists or not after operations
    assert any(path.iterdir()
               ), "There should be some file operations in the directory"


def test_file_creation(setup_syscheck_generator: tuple):
    """
    Test if files are being created by the generator.

    Args:
        setup_syscheck_generator (fixture): Fixture that provides a SyscheckEventGenerator and a path.
    """
    generator, path = setup_syscheck_generator
    generator.generate_event()  # Force a create event
    assert any(path.iterdir()), "Files should be created in the directory"


def test_file_modification(setup_syscheck_generator: tuple):
    """
    Test if files are being modified by the generator.

    Args:
        setup_syscheck_generator (fixture): Fixture that provides a SyscheckEventGenerator and a path.
    """
    generator, path = setup_syscheck_generator
    # Ensure a file is created first
    generator.create_file(str(path / "test_modify.txt"))
    original_content = "Initial content"
    with open(str(path / "test_modify.txt"), 'w') as f:
        f.write(original_content)
    generator.modify_file(str(path / "test_modify.txt"))
    with open(str(path / "test_modify.txt"), 'r') as f:
        content = f.read()
    assert content != original_content, "File should be modified"


def test_file_deletion(setup_syscheck_generator: tuple):
    """
    Test if files are being deleted by the generator.

    Args:
        setup_syscheck_generator (fixture): Fixture that provides a SyscheckEventGenerator and a path.
    """
    generator, path = setup_syscheck_generator
    file_path = str(path / "test_delete.txt")
    open(file_path, 'a').close()  # Create a file
    generator.delete_file(file_path)
    assert not os.path.exists(file_path), "File should be deleted"


def test_invalid_rate():
    """
    Test the behavior when an invalid rate (zero or negative) is provided.

    Expectation:
        Raises an exception due to invalid rate.
    """
    with pytest.raises(ValueError):
        SyscheckEventGenerator(rate=0, path="/tmp", operations=1)
