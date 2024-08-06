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
    $ python script.py --database-path /var/lib/sqlite --port 8000 --cert /etc/ssl/cert.pem --key /etc/ssl/key.pem --report-path /var/log/metrics.csv

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
import csv
import logging
import logging.config
import os
import sqlite3
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Optional

import brotli
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, Response
from starlette.requests import Request

from manager_mock_servers.manager_services.agent_comm_mock.models import AuthRequest, StatefullData, StatelessEvent
from manager_mock_servers.manager_services.agent_comm_mock.middlewares.brotli import BrotliMiddleware
from manager_mock_servers.utils.csv import init_csv_header, write_counts_to_csv

from manager_mock_servers.utils.token_manager import TokenManager
from manager_mock_servers.utils.vars import (
    DEFAULT_AUD,
    DEFAULT_EXPIRATION_TIME,
    DEFAULT_ISS,
    MANAGER_MOCK_TOKEN_SECRET_KEY,
)


logger = logging.getLogger('AgentCommMock')

report_file = 'metrics.csv'
metrics_header = ["Timestamp", "Event type", "Number of events", 'Stateless/Statefull']
router_version = APIRouter()

stateless_events_types = ['undeterminated']
statefull_events_types = ['undeterminated']

stateless_events: Dict[str, int] = {key: 0 for key in stateless_events_types}
statefull_events: Dict[str, int] = {key: 0 for key in statefull_events_types}
reset_interval = timedelta(seconds=10)
database_directory = os.path.join(os.path.abspath(__file__), 'agents.db')


@asynccontextmanager
async def lifespan(app: FastAPI):
    global database_directory
    global report_file

    init_csv_header(report_file, metrics_header)

    if not os.path.exists(database_directory):
        raise ValueError(f"Directory {database_directory} does not exist")

    logger.error(f"Database directory set to: {database_directory}")
    asyncio.create_task(reset_and_log_counts())

    yield

app = FastAPI(
    lifespan=lifespan
)

async def reset_and_log_counts():
    while True:
        await asyncio.sleep(reset_interval.total_seconds())
        measurement_datetime = datetime.utcnow().isoformat()

        for event_type in stateless_events_types:
            write_counts_to_csv(report_file, [measurement_datetime, event_type, statefull_events[event_type], 'stateless'])

        for event_type in statefull_events_types:
            write_counts_to_csv(report_file, [measurement_datetime, event_type, statefull_events[event_type], 'statefull'])


def set_database_path(db_path):
    global database_directory
    database_directory = db_path


async def get_token(authorization: Optional[str] = Header(None)) -> str:
    """Testing."""
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
async def authenticate(auth_request: AuthRequest):
    """Testing."""
    user_id = str(auth_request.uuid)
    key = auth_request.key

    conn = sqlite3.connect(database_directory)
    logger.error(database_directory)
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
        logger.error(key)
        logger.error(credential)

        return JSONResponse(status_code=409, content={'message': 'Invalid Key provided'})

    timestamp = int(datetime.now().timestamp())

    iat = timestamp
    exp = timestamp + DEFAULT_EXPIRATION_TIME
    token = TokenManager.generate_token(DEFAULT_ISS, DEFAULT_AUD, iat, exp, user_id, MANAGER_MOCK_TOKEN_SECRET_KEY)

    return JSONResponse(content={'token': token})


def get_event_type(event):
    return 'undeterminated'


@router_version.post('/events/stateless')
async def stateless_event(event: StatelessEvent, authorization: str = Depends(get_token)):
    """Testing."""
    global stateless_events
    stateless_events[get_event_type(event)] += 1

    return {'message': 'Event received'}


@router_version.post('/events/stateful')
async def stateful_event(event: StatefullData, authorization: str = Depends(get_token)):
    """Testing."""
    global statefull_events
    statefull_events[get_event_type(event)] += 1

    return {'message': 'Event is being processed and will be persisted'}

def set_report_file(report):
    global report_file
    report_file = report


def validate_parameters():
    pass

def main():
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')

    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory',
                        dest="database_path")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")
    parser.add_argument('--cert', type=str, required=True, help='SSL certificate file', dest="cert")
    parser.add_argument('--key', type=str, required=True, help='SSL key file', dest="key")
    parser.add_argument('--report-path', type=str, required=True, help='Metrics report CSV file path', dest="report_path")
    parser.add_argument('--api-version', type=str, required=False, help='API version', dest="api_version", default='/v1')


    global database_directory

    args = parser.parse_args()

    set_report_file(args.report_path)

    # Register the routers with the main app
    app.include_router(router_version, prefix=args.api_version)
    app.add_middleware(BrotliMiddleware)

    database_directory = args.database_path
    uvicorn.run(app, host='0.0.0.0', port=args.port, ssl_keyfile=args.key, ssl_certfile=args.cert)


if __name__ == "__main__":
    main()
