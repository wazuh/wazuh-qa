# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Mock Server Manager.

This module provides a script for managing and running mock server services for testing. It supports starting
server and agent communication services, generating SSL certificates, and handling process management.

### Usage:
Run the script with the following command:

```sh
simulate-manager --manager-api-port <management-port> --agent-comm-api-port <agent-comm-port> \
--server-path </path/to/server> --report-path </path/to/report.csv> --api-version /v1 --debug
```

### Arguments:
    --report-path: Path to the CSV file for metrics (required).
    --manager-api-port: Port for the management service (default: 55000).
    --agent-comm-api-port: Port for the agent communication service (default: 2900).
    --server-path: Directory for server files (optional; uses a temporary directory if not specified).
    --api-version: API version (e.g., /v1).
    --debug: Enable debug mode.

This script helps simulate server behavior for testing and development.
"""
