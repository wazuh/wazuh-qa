## Overview

The Manager Agent Comm API Mocker is a mock server designed to handle agent authentication and manage events sent by agents. It uses FastAPI for the web framework and SQLite for storing agent data. This mock server simulates the behavior of a real agent communication server, facilitating testing and development.

## Usage

To start the mock server, use the following command:

```bash
python script.py --database-path /path/to/db \
    --port 8000 \
    --cert /path/to/cert \
    --key /path/to/key \
    --report-path /path/to/metrics.csv \
    --api-version /v1
```

### Arguments

    --database-path: Path to the SQLite database directory.
    --port: Port number for the FastAPI server.
    --cert: Path to the SSL certificate file.
    --key: Path to the SSL key file.
    --report-path: Path to the CSV file where metrics will be logged.
    --api-version: API version prefix (default is /v1).

### Example

```bash
python script.py --database-path /var/lib/sqlite --port 8000 --cert /etc/ssl/cert.pem --key /etc/ssl/key.pem --report-path /var/log/metrics.csv
```

## Files

    metrics.csv: The CSV file used for logging metrics.
