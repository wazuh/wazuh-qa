# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
r"""Manager Agent Comm API Mocker.

This module implements a mock Agent Comm server for managing agent authentication and events sent.
It uses FastAPI for the web framework and SQLite for agent data storage.

Usage:
    To start the server, run the script with the required arguments. Example:
    $ python script.py --database-path /path/to/db \
        --port 8000 \
        --cert /path/to/cert \
        --key /path/to/key \
        --report-path /path/to/metrics.csv
        --api-version api-version

Arguments:
    --database-path: The path to the SQLite database directory.
    --port: The port number on which the FastAPI server will run.
    --cert: The path to the SSL certificate file.
    --key: The path to the SSL key file.
    --report-path: The path to the CSV file where metrics will be logged.
    --api-version: The API version prefix (default is '/v1').

Example:
    $ python script.py --database-path /var/lib/sqlite --port 8000 --cert /etc/ssl/cert.pem --key /etc/ssl/key.pem \
    --report-path /var/log/metrics.csv

Environment Variables:
    None.

Files:
    - metrics.csv: The CSV file used for logging metrics.

Logging:
    - Logs are created and managed using the Python logging module.
    - Errors related to database connections and token validation are logged.

References:
    - https://github.com/wazuh/wazuh/issues/24685
    - https://github.com/wazuh/wazuh/issues/24294

Dependencies:
    - FastAPI
    - Uvicorn
    - SQLite
    - Brotli
"""
import argparse
import asyncio
import logging
import logging.config
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Optional, AsyncGenerator

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from manager_mock_services.agent_comm_mock.middlewares.brotli import BrotliMiddleware
from manager_mock_services.agent_comm_mock.models import AuthRequest, StatefullEvents, StatelessEvents
from utils.csv import init_csv_header, write_row_to_csv
from utils.token_manager import TokenManager
from utils.vars import (
    DEFAULT_AUD,
    DEFAULT_EXPIRATION_TIME,
    DEFAULT_ISS,
    MANAGER_MOCK_TOKEN_SECRET_KEY,
)


logger = logging.getLogger('uvicorn.error')

report_file = 'metrics.csv'
metrics_header = ["Timestamp", "Event type", "Number of events", 'Stateless/Statefull']
router_version = APIRouter()

stateless_events_types = ['undeterminated']
statefull_events_types = ['undeterminated']

stateless_events_counts: Dict[str, int] = {key: 0 for key in stateless_events_types}
statefull_events_counts: Dict[str, int] = {key: 0 for key in statefull_events_types}
reset_interval = timedelta(seconds=10)
database_directory = os.path.join(os.path.abspath(__file__), 'agents.db')


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initializes the application lifespan.

    Set up the CSV file for metrics logging and verifying the existence of the database directory.
    Also it starts a periodic task to reset and log event counts.

    Args:
        app (FastAPI): The FastAPI application instance.

    Yields:
        None: Context manager that yields control to the application during its lifespan.

    Raises:
        ValueError: If the database directory does not exist.
    """
    global database_directory
    global report_file

    init_csv_header(report_file, metrics_header)

    if not os.path.exists(database_directory):
        raise ValueError(f"Directory {database_directory} does not exist")

    logger.info(f"Database directory set to: {database_directory}")
    asyncio.create_task(reset_and_log_counts())

    yield

app = FastAPI(
    lifespan=lifespan
)


async def reset_and_log_counts() -> None:
    """Periodically resets the event counts and logs them to the CSV file.

    This function runs in an infinite loop, sleeping for a predefined interval, then writing
    the current counts of stateless and stateful events to the CSV file.
    """
    while True:
        await asyncio.sleep(reset_interval.total_seconds())
        measurement_datetime = datetime.now().isoformat()

        for event_type in stateless_events_types:
            write_row_to_csv(report_file, [measurement_datetime, event_type,
                                           statefull_events_counts[event_type], 'stateless'])

        for event_type in statefull_events_types:
            write_row_to_csv(report_file, [measurement_datetime, event_type,
                                           statefull_events_counts[event_type], 'statefull'])


def set_database_path(db_path: str) -> None:
    """Sets the path to the SQLite database directory.

    Args:
        db_path (str): The new path to the SQLite database directory.
    """
    global database_directory
    database_directory = db_path


async def get_token(authorization: Optional[str] = Header(None)) -> str:
    """Retrieves and validates the token from the Authorization header.

    Args:
        authorization (Optional[str]): The Authorization header from the request, expected
        to be in the format "Bearer <token>".

    Returns:
        str: The validated token.

    Raises:
        HTTPException: If the Authorization header is missing, malformed, or the token is invalid or expired.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or malformed")
    try:
        token = authorization.split(" ")[1]
        TokenManager.decode_token(token, DEFAULT_ISS, DEFAULT_AUD, MANAGER_MOCK_TOKEN_SECRET_KEY)
    except Exception as decode_token_error:
        logger.critical(decode_token_error)
        raise HTTPException(status_code=401, detail="Token has expired") from decode_token_error

    return token


@router_version.post('/authentication')
async def authenticate(auth_request: AuthRequest) -> JSONResponse:
    """Authenticates an agent and returns a JWT token if the authentication is successful.

    Args:
        auth_request (AuthRequest): The authentication request containing the agent UUID and optional key.

    Returns:
        JSONResponse: A response containing the JWT token if authentication is successful,
                      or an error message if the agent does not exist or the key is invalid.
    """
    user_id = str(auth_request.uuid)
    key = auth_request.key

    conn = sqlite3.connect(database_directory)
    cursor = conn.cursor()

    cursor.execute(f'SELECT * FROM agents WHERE uuid = "{user_id}"')
    existing_agent = cursor.fetchone()
    cursor.execute(f'SELECT credential FROM agents WHERE uuid = "{user_id}"')
    credential = cursor.fetchone()

    conn.commit()
    conn.close()

    if not existing_agent:
        return JSONResponse(status_code=409, content={'message': 'Agent with uuid does not exist'})
    if not credential or key != credential[0]:
        return JSONResponse(status_code=409, content={'message': 'Invalid Key provided'})

    timestamp = int(datetime.now().timestamp())

    iat = timestamp
    exp = timestamp + DEFAULT_EXPIRATION_TIME
    token = TokenManager.generate_token(DEFAULT_ISS, DEFAULT_AUD, iat, exp, user_id, MANAGER_MOCK_TOKEN_SECRET_KEY)

    return JSONResponse(content={'token': token})


def count_statefull_events(statefull_events: StatelessEvents) -> None:
    """Determines the type of the event. This function currently returns a placeholder value.

    Args:
        statefull_events (StatelessEvent): The event data.

    TODO: Replace this logic when events format has been determinated
    """
    global statefull_events_counts

    for _ in statefull_events.events:
        statefull_events_counts['undeterminated'] += 1


def count_stateless_events(stateless_events: StatelessEvents) -> None:
    """Count received stateless events types.

    Args:
        stateless_events (StatelessEvent): The event data.

    TODO: Replace this logic when events format has been determinated
    """
    global stateless_events_counts

    for _ in stateless_events.events:
        stateless_events_counts['undeterminated'] += 1


@router_version.post('/events/stateless')
async def stateless_event(event: StatelessEvents, authorization: str = Depends(get_token)):
    """Handles stateless events and increments the count for the corresponding event type.

    Args:
        event (StatelessEvent): The stateless event data.
        authorization (str): The valid JWT token for authorization.

    Returns:
        dict: A message confirming the receipt of the event.
    """
    count_stateless_events(event)

    return {'message': 'Event received'}


@router_version.get('/commands')
async def get_commands(authorization: str = Depends(get_token)):
    """Mocked command endpoint.

    Emulate the behaviour of agent_comm commands endpoint in case of no new commands, returning a request timeout

    Raises:
        HTTPException: Requests timeout exception.
    """
    raise HTTPException(status_code=408)


@router_version.post('/events/stateful')
async def stateful_event(event: StatefullEvents, authorization: str = Depends(get_token)) -> dict:
    """Handles stateful events and increments the count for the corresponding event type.

    Args:
        event (StatefullData): The stateful event data.
        authorization (str): The valid JWT token for authorization.

    Returns:
        dict: A message confirming that the event is being processed.
    """
    count_statefull_events(event)

    return {'message': 'Event is being processed and will be persisted'}


def set_report_file(report: str) -> None:
    """Sets the path for the metrics CSV file.

    Args:
        report (str): The path to the CSV file where metrics will be logged.
    """
    global report_file
    report_file = report


def parse_parameters() -> argparse.Namespace:
    """Parse script parameters.

    Rerturns:
        argparse.Namespace: Namespace with parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Start FastAPI with database path',
                                     usage=('%(prog)s --database-path <db_path> --port '
                                            '<port> --cert <cert_file> --key <key_file>'
                                            '--report-path <report_file> [--api-version <api_version>] [-v]'),
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory',
                        dest="database_path")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")
    parser.add_argument('--cert', type=str, required=True, help='SSL certificate file', dest="cert")
    parser.add_argument('--key', type=str, required=True, help='SSL key file', dest="key")
    parser.add_argument('--report-path', type=str, required=True, help='Metrics report CSV file path',
                        dest="report_path")
    parser.add_argument('--api-version', type=str, required=False, help='API version', dest="api_version",
                        default='/v1')
    parser.add_argument('-v', '--debug',
                        help='Enable debug mode',
                        required=False,
                        action='store_true',
                        default=False,
                        dest='debug')

    args = parser.parse_args()

    return args


def validate_parameters(args: argparse.Namespace) -> None:
    """Validates command-line arguments for starting the FastAPI server.

    Args:
        args (argparse.Namespace): The command-line arguments parsed by argparse.

    Raises:
        ValueError: If any argument fails validation checks, such as incorrect API version format,
                    missing or invalid file paths, or invalid port number.
    """
    # Validate API version
    if not args.api_version.startswith('/'):
        raise ValueError("API version should start with '/'")

    # Validate port number
    if not (1 <= args.port <= 65535):
        raise ValueError("Port number should be between 1 and 65535")

    # Validate file paths
    def validate_file_path(path: str):
        if not os.path.isfile(path):
            raise ValueError(f"File not found: {path}")

    # Validate SSL certificate and key files
    validate_file_path(args.cert)
    validate_file_path(args.key)

    # Validate database directory (should be a directory, not a file)
    if not os.path.isdir(args.database_path):
        raise ValueError(f"Directory not found: {args.database_path}")


def main():
    """Parses command-line arguments, configures the FastAPI app, and runs the server.

    Parses the necessary command-line arguments, sets up the application, and starts the Uvicorn server
    to run the FastAPI application with the provided configuration.
    """
    global database_directory

    args = parse_parameters()
    validate_parameters(args)

    set_report_file(args.report_path)

    # Register the routers with the main app
    app.include_router(router_version, prefix=args.api_version)
    app.add_middleware(BrotliMiddleware)

    database_directory = os.path.join(args.database_path, 'agents.db')
    uvicorn.run(app, host='0.0.0.0', port=args.port, ssl_keyfile=args.key, ssl_certfile=args.cert)


if __name__ == "__main__":
    main()
