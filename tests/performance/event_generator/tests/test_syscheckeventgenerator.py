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
    rate = 1
    operations = 6
    generator = SyscheckEventGenerator(
        rate=rate,
        path=str(path),
        operations=operations
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
    rate = 2
    operations = 10
    expected_duration = operations / rate

    generator = SyscheckEventGenerator(
        rate=rate,
        path=str(path),
        operations=operations
    )

    start_time = time.time()
    generator.start()
    end_time = time.time()
    actual_duration = end_time - start_time

    allowed_margin = expected_duration * 0.05  # Allow a 5% margin
    lower_bound = expected_duration - allowed_margin
    upper_bound = expected_duration + allowed_margin

    assert lower_bound <= actual_duration <= upper_bound, (
        f"Event generation took {actual_duration:.2f}s, expected approximately {expected_duration:.2f}s"
    )


def test_invalid_rate():
    """Test the behavior when an invalid rate (zero or negative) is provided.

    Expectation:
        Raises an exception due to invalid rate.
    """
    with pytest.raises(ValueError):
        SyscheckEventGenerator(rate=0, path="/tmp", operations=1)
