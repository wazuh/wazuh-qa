# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Unit tests for the LogEventGenerator class."""

import json
import os
import time
import threading
from pathlib import Path

import pytest

from event_generator import LogEventGenerator


@pytest.fixture
def log_generator(tmp_path: Path) -> LogEventGenerator:
    """Fixture that provides a LogEventGenerator instance with a unique log file for each test.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
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


@pytest.mark.parametrize("rate, operations", [
    (1, 5),
    (10, 50),
    (100, 1000),
])
def test_log_event_count_parametrized(tmp_path: Path, rate: int, operations: int) -> None:
    """Test if the correct number of log events are generated with different rates and operations.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
        rate (int): Number of operation per second.
        operations (int): number of times logs will be generated.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(
        rate=rate,
        path=str(path),
        operations=operations,
        max_file_size=None,
        template_path=None
    )

    expected_duration = operations / rate

    start_time = time.time()
    generator.start()
    end_time = time.time()
    actual_duration = end_time - start_time

    allowed_margin = expected_duration * 0.05  # Allow a 5% of margin
    lower_bound = expected_duration - allowed_margin
    upper_bound = expected_duration + allowed_margin

    assert lower_bound <= actual_duration <= upper_bound, (
        f"Generator took {actual_duration:.2f}s, expected approximately {expected_duration:.2f}s"
    )

    with open(path) as file:
        lines = file.readlines()
    assert len(lines) == operations, f"Exactly {operations} log entries should be written."


def test_zero_operations(tmp_path: Path) -> None:
    """Test no log file creation when operations are set to zero.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(
        rate=1,
        path=str(path),
        operations=0,
        max_file_size=1,
        template_path=None
    )
    generator.start()
    assert not path.exists(), "Log file should not exist when no operations are specified."


def test_invalid_path() -> None:
    """Test behavior when an invalid path is provided.

    Expectation:
        Raises an OSError due to invalid path.
    """
    with pytest.raises(OSError):
        LogEventGenerator(
            rate=1,
            path="/invalid/path",
            operations=1,
            max_file_size=1,
            template_path=None
        )


def test_high_rate(tmp_path: Path) -> None:
    """Test the system's response to a very high event generation rate.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    generator = LogEventGenerator(
        rate=10000,
        path=str(path),
        operations=100,
        max_file_size=1,
        template_path=None
    )
    generator.start()
    assert path.exists(), "Log file should still be created with high rate."
    with open(path) as file:
        lines = file.readlines()
    assert len(lines) == 100, "Exactly 100 log entries should be written."


def test_log_rotation(tmp_path: Path) -> None:
    """Test that log rotation occurs when the max file size is exceeded.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    max_file_size_mb = 1 / 1024  # 1 KB in MB
    max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)  # Convert MB to bytes

    generator = LogEventGenerator(
        rate=50,
        path=str(path),
        operations=200,
        max_file_size=max_file_size_mb,
        template_path=None
    )

    file_sizes = []
    rotation_detected = False

    # Run the generator in a separate thread
    generator_thread = threading.Thread(target=generator.start)
    generator_thread.start()

    try:
        # Monitor the file size while the generator is running
        while generator_thread.is_alive():
            if path.exists():
                file_size = os.path.getsize(path)
                file_sizes.append(file_size)
                # Check if file size exceeds max_file_size
                assert file_size <= max_file_size_bytes, (
                    f"File size exceeded max_file_size during execution: {file_size} bytes"
                )
                # Detect rotation by checking if file size decreases
                if len(file_sizes) >= 2 and file_sizes[-1] < file_sizes[-2]:
                    rotation_detected = True
            time.sleep(0.1)
    finally:
        generator_thread.join()

    assert rotation_detected, "Log file was not rotated during the test."


def test_template_formatting(tmp_path: Path) -> None:
    """Test that log entries are formatted according to the provided template.

    Args:
        tmp_path (LocalPath): Temporary directory path fixture provided by pytest.
    """
    path = tmp_path / "test.log"
    custom_template = {
        "timestamp": "{date} {time}",
        "level": "{severity}",
        "msg": "{message}"
    }
    template_path = tmp_path / "template.json"
    with open(template_path, 'w') as f:
        json.dump(custom_template, f)
    generator = LogEventGenerator(
        rate=1,
        path=str(path),
        operations=1,
        max_file_size=None,
        template_path=str(template_path)
    )
    generator.start()
    with open(path) as file:
        content = file.read()
    assert '"timestamp":' in content, "Log entry should include custom 'timestamp' field from template."
    assert '"level":' in content, "Log entry should include custom 'level' field from template."
    assert '"msg":' in content, "Log entry should include custom 'msg' field from template."
