# Manager Management API Mocker

## Overview

The Manager Management API Mocker is a module designed to simulate a Wazuh management server. It handles agent authentication and registration using FastAPI for the web framework and SQLite for data storage. This mock server allows you to test agent management functionalities without needing a full Wazuh setup.

## Features

- **Authentication**: Provides an endpoint to authenticate users and generate JWT tokens.
- **Agent Registration**: Allows registration of new agents and checks for duplicate entries.
- **Secure Connections**: Supports SSL/TLS encryption for secure communication.
- **Database Storage**: Uses SQLite to manage agent data.


## Configuration

You need to provide SSL/TLS certificates and a database path to run the server. Ensure you have the following files in place:

- `certs/private_key.pem` - SSL private key file
- `certs/certificate.pem` - SSL certificate file
- `database/agents.db` - SQLite database file for storing agent data

## Usage

To start the server, use the following command:

```bash
python3 manager_server_mock.py --port 2700 --key certs/private_key.pem --cert certs/certificate.pem --database-path database/agents.db
```

### Arguments

- `--database-path`: Path to the directory where the SQLite database is located.
- `--key`: Path to the SSL private key file.
- `--cert`: Path to the SSL certificate file.
- `--port`: Port number on which the server will listen.


### Example

```bash
python3 manager_server_mock.py --port 2700 --key certs/private_key.pem --cert certs/certificate.pem --database-path database/agents.db
```
