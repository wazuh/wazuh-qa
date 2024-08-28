# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the LogEventGenerator class."""

import os
import pytest
import time
from event_generator import LogEventGenerator


@pytest.fixture
def setup_log_generator(tmp_path):
    """
    Setup for LogEventGenerator with a temporary directory.

    Args:
        tmp_path (LocalPath): Provides a temporary directory path fixture from pytest.

    Returns:
        tuple: A tuple containing an instance of LogEventGenerator and the path to the log file.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(rate=1, path=str(
        path), operations=5, max_file_size=1, template_path=None)
    return generator, path


def test_log_creation(setup_log_generator):
    """
    Test if log files are created correctly.

    Args:
        setup_log_generator (fixture): Fixture that provides a log generator and a path.
    """
    generator, path = setup_log_generator
    generator.start()
    assert path.exists(), "Log file should exist after generation start"


def test_log_content(setup_log_generator):
    """
    Test the content of log files to ensure logs are written.

    Args:
        setup_log_generator (fixture): Fixture that provides a log generator and a path.
    """
    generator, path = setup_log_generator
    generator.start()
    with open(path, 'r') as file:
        content = file.read()
    assert "This is a test log message" in content, "Log message should be in the log file"


def test_zero_operations(tmp_path):
    """
    Test no log file creation when operations are set to zero.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(rate=1, path=str(
        path), operations=0, max_file_size=1, template_path=None)
    generator.start()
    assert not path.exists(), "Log file should not exist when no operations are specified"


def test_invalid_path():
    """
    Test behavior when an invalid path is provided.

    Expectation:
        Raises an exception due to invalid path.
    """
    generator = LogEventGenerator(
        rate=1, path="/invalid/path", operations=1, max_file_size=1, template_path=None)
    with pytest.raises(Exception):
        generator.start()


def test_high_rate(tmp_path):
    """
    Test the system's response to a very high event generation rate.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(rate=10000, path=str(
        path), operations=100, max_file_size=1, template_path=None)
    generator.start()
    assert path.exists(), "Log file should still be created with high rate"
    with open(path, 'r') as file:
        lines = file.readlines()
    assert len(lines) == 100, "Exactly 100 log entries should be written"
