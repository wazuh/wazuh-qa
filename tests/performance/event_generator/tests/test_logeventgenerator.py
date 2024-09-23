# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the LogEventGenerator class."""

from pathlib import Path

import json
import os
import pytest

from event_generator import LogEventGenerator


@pytest.fixture
def log_generator(tmp_path: Path) -> LogEventGenerator:
    """Fixture that provides a LogEventGenerator instance with a unique log file for each test."""
    path = tmp_path / "test.log"
    generator = LogEventGenerator(
        rate=1,
        path=str(path),
        operations=5,
        max_file_size=1,
        template_path=None
    )
    return generator


def test_log_file_exists(log_generator: LogEventGenerator) -> None:
    """Test if the log file is created."""
    generator = log_generator
    generator.start()
    assert os.path.exists(generator.path), "Log file should exist after generation."


def test_log_event_count(log_generator: LogEventGenerator) -> None:
    """Test if the correct number of log events are generated."""
    generator = log_generator
    generator.start()
    with open(generator.path) as file:
        lines = file.readlines()
    assert len(lines) == generator.operations, f"Exactly {generator.operations} log entries should be written."


def test_log_content(log_generator: LogEventGenerator) -> None:
    """Test the content of the log file."""
    generator = log_generator
    generator.start()
    with open(generator.path) as file:
        content = file.read()
    assert "This is a test log message" in content, "Log message should be in the log file."


def test_zero_operations(tmp_path: Path) -> None:
    """Test no log file creation when operations are set to zero.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(rate=1, path=str(
        path), operations=0, max_file_size=1, template_path=None)
    generator.start()
    assert not path.exists(), "Log file should not exist when no operations are specified"


def test_invalid_path() -> None:
    """Test behavior when an invalid path is provided.

    Expectation:
        Raises an IOError due to invalid path.
    """
    generator = LogEventGenerator(
        rate=1, path="/invalid/path", operations=1, max_file_size=1, template_path=None)
    with pytest.raises(IOError):
        generator.start()


def test_high_rate(tmp_path: Path) -> None:
    """Test the system's response to a very high event generation rate.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(rate=10000, path=str(
        path), operations=100, max_file_size=1, template_path=None)
    generator.start()
    assert path.exists(), "Log file should still be created with high rate"
    with open(path) as file:
        lines = file.readlines()
    assert len(lines) == 100, "Exactly 100 log entries should be written"
