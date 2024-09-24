# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the SyscheckEventGenerator class."""

from pathlib import Path

import pytest
import time

from event_generator import SyscheckEventGenerator


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


def test_syscheck_rate(tmp_path: Path):
    """Test that SyscheckEventGenerator respects the provided rate.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path
    num_files = 2
    num_modifications = 1
    operations = num_files + (num_files * num_modifications) + num_files  # create + modify + delete
    rate = 2  # 2 events per second
    expected_duration = operations / rate

    generator = SyscheckEventGenerator(
        rate=rate,
        path=str(path),
        operations=operations,
        num_files=num_files,
        num_modifications=num_modifications
    )

    start_time = time.time()
    generator.start()
    end_time = time.time()
    actual_duration = end_time - start_time

    # Allow a small margin for processing time
    assert abs(actual_duration - expected_duration) < 0.5, (
        f"Event generation took {actual_duration:.2f}s, expected approximately {expected_duration:.2f}s"
    )


def test_invalid_rate():
    """Test the behavior when an invalid rate (zero or negative) is provided.

    Expectation:
        Raises an exception due to invalid rate.
    """
    with pytest.raises(ValueError):
        SyscheckEventGenerator(rate=0, path="/tmp", operations=1)
