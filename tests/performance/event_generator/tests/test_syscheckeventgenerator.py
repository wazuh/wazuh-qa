# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the SyscheckEventGenerator class."""

from pathlib import Path

import pytest

from event_generator import SyscheckEventGenerator


@pytest.fixture
def setup_syscheck_generator(tmp_path: Path) -> tuple:
    """Setup for SyscheckEventGenerator with a temporary directory.

    Args:
        tmp_path (LocalPath): Temporary directory provided by pytest.

    Returns:
        tuple: A tuple containing an instance of SyscheckEventGenerator and the path to the directory.
    """
    path = tmp_path
    generator = SyscheckEventGenerator(rate=1, path=str(path), operations=5)
    return generator, path


def test_syscheck_operations(tmp_path: Path):
    """Test that SyscheckEventGenerator performs create, modify, and delete operations as expected.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path
    num_files = 2
    num_modifications = 1
    operations = num_files + (num_files * num_modifications) + num_files  # create + modify + delete
    generator = SyscheckEventGenerator(
        rate=1,
        path=str(path),
        operations=operations,
        num_files=num_files,
        num_modifications=num_modifications
    )
    generator.start()
    # After all operations, the directory should be empty
    files = list(path.iterdir())
    assert len(files) == 0, "All files should have been deleted after all operations."


def test_invalid_rate():
    """Test the behavior when an invalid rate (zero or negative) is provided.

    Expectation:
        Raises an exception due to invalid rate.
    """
    with pytest.raises(ValueError):
        SyscheckEventGenerator(rate=0, path="/tmp", operations=1)
