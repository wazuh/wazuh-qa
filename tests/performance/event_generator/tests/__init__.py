# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Test suite initialization for the event generator module.

This module initializes test configurations and shared fixtures for testing the event_generator package.
It supports testing functionalities such as log file generation, system event simulation, and file operations.

### Structure:
- test_logeventgenerator.py: Tests the logging capabilities of the log event generator.
- test_syscheckeventgenerator.py: Tests the file operation simulation for system integrity checks.

### Usage:

Utilize pytest to run individual test modules or the entire suite:

```sh
pytest tests/test_logeventgenerator.py
pytest tests/test_syscheckeventgenerator.py
pytest
```
"""
