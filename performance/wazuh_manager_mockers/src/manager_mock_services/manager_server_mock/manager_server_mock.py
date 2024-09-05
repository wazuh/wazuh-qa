# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
r"""Manager Management API Mocker.

This module implements a mock Wazuh management server for managing agent registration.
It uses FastAPI for the web framework and SQLite for agent data storage.

Usage:
    $ python3 manager_server_mock.py \
      --port 2700 \
      --key certs/private_key.pem \
      --cert certs/certificate.pem \
      --database_path database/agents.db

Arguments:
    --database-path  Path to the database directory.
    --key            Path to the SSL private key file.
    --cert           Path to the SSL certificate file.
    --port           Port number to run the server on.

Example:
    $ python3 manager_server_mock.py --port 2700 --key certs/private_key.pem --cert certs/certificate.pem --database_path database/agents.db

Environment Variables:
    None.

Files:
    certs/private_key.pem      SSL private key file.
    certs/certificate.pem      SSL certificate file.
    database/agents.db         SQLite database file for storing agent data.

Logging:
    The server logs using the 'uvicorn.error' logger.

References:
    - https://github.com/wazuh/wazuh/issues/24685
    - https://github.com/wazuh/wazuh/issues/24294

Dependencies:
    - FastAPI
    - Uvicorn
    - SQLite
"""
import argparse
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, AsyncGenerator

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from manager_mock_services.manager_server_mock.models import AgentData, AuthData
from utils.token_manager import TokenManager
from utils.agent_database_handler import insert_new_agent, check_if_agent_exists, check_if_uuid_exists, \
    create_agents_database
from utils.vars import (
    DEFAULT_AUD,
    DEFAULT_EXPIRATION_TIME,
    DEFAULT_ISS,
    MANAGER_MOCK_TOKEN_SECRET_KEY,
)

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.INFO)

DATABASE_PATH = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Context manager for managing the lifespan of a Management API.

    This context manager ensures that provided database exists before application starts.

    Preconditions:
    - Checks if the database directory specified by `DATABASE_PATH` exists.
      If the directory does not exist, raises a `ValueError`.

    Args:
        app (FastAPI): The FastAPI application instance.

    Yields:
        None
    """
    if not os.path.exists(DATABASE_PATH):
        raise ValueError(f"Directory {DATABASE_PATH} does not exist")

    yield


async def get_token(authorization: Optional[str] = Header(None)) -> str:
    """Extract and validate a JWT token from the Authorization header.

    Args:
        authorization (Optional[str]): The Authorization header value. Should be in the format "Bearer <token>".

    Returns:
        str: The extracted and validated JWT token.

    Raises:
        HTTPException: If the Authorization header is missing, malformed, or if the token is invalid.
            - 401: If the Authorization header is missing or not starting with "Bearer ".
            - 403: If the JWT token is invalid.

    Example:
        To call this function, include an Authorization header in your request:

            headers = {"Authorization": "Bearer <your_jwt_token>"}
            response = await get_token(authorization=headers["Authorization"])
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or malformed")

    token = authorization.split(" ")[1]

    try:
        TokenManager.decode_token(token, DEFAULT_ISS, DEFAULT_AUD, MANAGER_MOCK_TOKEN_SECRET_KEY)
    except Exception as exception:
        raise HTTPException(status_code=403, detail="Invalid JWT token") from exception

    return token

def start_server_manager(app: FastAPI, database_path: str, port: int,
                         ssl_keyfile: str, ssl_certfile: str) -> None:
    """Starts Management API service.

    This function configures the server to use the specified database path and starts
    the server with SSL encryption. It uses `uvicorn` to run the server.

    Args:
        application (FastAPI): The FastAPI application instance to be served.
        database_path (str): The path to the database directory. This is used to configure
                             the application's database access.
        port (int): The port number on which the server will listen.
        ssl_keyfile (str): The file path to the SSL key file for secure connections.
        ssl_certfile (str): The file path to the SSL certificate file for secure connections.
    """
    set_database_path(database_path)
    uvicorn.run(app, host='0.0.0.0', port=port, ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile)


def set_database_path(db_path: str) -> None:
    """Sets the global path for the database used by Management API.

    This function updates the global `DATABASE_PATH` variable to the provided path.

    Args:
        db_path (str): The path to the database directory. This path will be used
                       to locate or initialize the database.
    """
    global DATABASE_PATH
    create_agents_database(db_path)
    DATABASE_PATH = os.path.join(db_path, 'agents.db')


app = FastAPI(
    lifespan=lifespan
)


@app.post("/authentication")
async def authenticate(data: AuthData) -> JSONResponse:
    """Authenticates a user and generates a JWT token.

    This endpoint receives authentication data, which includes user credentials, and
    generates a JSON Web Token (JWT) upon successful processing. The token includes
    a timestamp indicating when the token was issued and an expiration time.

    Args:
        data (AuthData): The authentication data containing user credentials.

    Returns:
        JSONResponse: A JSON response containing the generated JWT token.

    Raises:
        HTTPException: If authentication fails or any other errors occur during processing.

    Example:
        Request:
        POST /authentication
        {
            "user": "example_user",
            "password": "example_password"
        }

        Response:
        {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp.."
        }
    """
    timestamp = int(datetime.now().timestamp())
    exp = timestamp + DEFAULT_EXPIRATION_TIME

    token = TokenManager.generate_token(DEFAULT_ISS, DEFAULT_AUD, timestamp, exp,
                                        data.user, MANAGER_MOCK_TOKEN_SECRET_KEY)

    return JSONResponse(content={'token': token})


@app.post("/agents")
async def agents(data: AgentData, authorization: str = Depends(get_token)) -> JSONResponse:
    """Registers a new agent in the system.

    This endpoint accepts agent registration data and checks whether an agent
    with the given credentials already exists. If not, it inserts the new agent
    into the database.

    Args:
        data (AgentData): The data for the agent registration, including `uuid`, `key`, and `name`.
        authorization (str): The authorization token required to access the endpoint,
                             obtained through a dependency (`get_token`).

    Returns:
        JSONResponse: A JSON response with a success message if the registration is successful,
                      or an error message if there are issues such as missing parameters or
                      a conflict with existing credentials.

    Raises:
        HTTPException:
            - 400 Bad Request: If no input data is provided or if required parameters are missing.
            - 409 Conflict: If an agent with the same credentials is already registered.
            - 500 Internal Server Error: For unexpected database errors.

    Example:
        Request:
        POST /agents
        Headers:
            Authorization: Bearer <token>
        Body:
        {
            "uuid": "agent-uuid",
            "key": "agent-key",
            "name": "agent-name"
        }

        Response:
        Success:
        {
            "message": "Agent was correctly registered"
        }

        Conflict:
        {
            "error": "Agent with this credential already registered",
            "uuid": "existing-agent-uuid"
        }

        Error:
        {
            "detail": "No input data provided" or "Missing parameters!" or "Unexpected database error <error-details>"
        }
    """
    if not data:
        raise HTTPException(status_code=400, detail="No input data provided")

    uuid, key, name = data.uuid, data.key, data.name

    if not uuid or not key or not key or not name:
        raise HTTPException(status_code=400, detail="Missing parameters!")

    try:
        existing_agent = check_if_agent_exists(DATABASE_PATH, name)
        existing_uuid = check_if_uuid_exists(DATABASE_PATH, str(uuid))
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        existing_agent = False
        existing_uuid = False

    if existing_agent:
        return JSONResponse(status_code=409, content={'error': 'Agent with this credential already registered',
                                                      'name': name})
    if existing_uuid:
        return JSONResponse(status_code=409, content={'error': 'Agent with this credential already registered',
                                                      'uuid': str(uuid)})

    try:
        insert_new_agent(DATABASE_PATH, uuid, key, name)
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected database error {e}") from e

    return JSONResponse(content={'message': 'Agent was correctly registered'})


def parse_arguments() -> argparse.Namespace:
    """Parse script parameters."""
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')
    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory',
                        dest="database_path")
    parser.add_argument('--key', type=str, required=True, help='Key path', dest="key")
    parser.add_argument('--cert', type=str, required=True, help='Cert path', dest="cert")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")
    parser.add_argument('-v', '--debug',
                        help='Enable debug mode',
                        required=False,
                        action='store_true',
                        default=False,
                        dest='debug')

    return parser.parse_args()


def main():
    """Entry point for starting the FastAPI server with specified configuration.

    This function sets up and parses command-line arguments required for running
    the Management API server. It expects arguments for the database path, SSL/TLS certificate,
    private key, and server port. After parsing the arguments, it starts the server
    using the `start_server_manager` function.

    Command-line arguments:
        --database-path (str): Required. Path to the directory where the database is located.
        --key (str): Required. Path to the SSL/TLS private key file for securing the connection.
        --cert (str): Required. Path to the SSL/TLS certificate file for securing the connection.
        --port (int): Required. Port number on which the FastAPI server will listen for incoming requests.

    Example usage:
        python script.py --database-path /path/to/database --key /path/to/key.pem --cert /path/to/cert.pem --port 8000

    This function does not return any value. It initiates the FastAPI server and blocks execution
    while the server is running.

    Raises:
        ArgumentTypeError: If any of the provided arguments do not match the expected types.
    """
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')
    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory',
                        dest="database_path")
    parser.add_argument('--key', type=str, required=True, help='Key path', dest="key")
    parser.add_argument('--cert', type=str, required=True, help='Cert path', dest="cert")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")
    parser.add_argument('-v', '--debug',
                            help='Enable debug mode',
                            required=False,
                            action='store_true',
                            default=False,
                            dest='debug')

    args = parser.parse_args()
    start_server_manager(app, args.database_path, args.port, args.key, args.cert)


if __name__ == "__main__":
    main()
