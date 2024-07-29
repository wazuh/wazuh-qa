from fastapi import FastAPI, HTTPException, Depends, Request, status, Query, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
import uvicorn
from typing import Optional
import logging

from datetime import datetime, timedelta
import sqlite3

import argparse
import os

from contextlib import asynccontextmanager
from models import AuthData, AgentData, TokenManager


# Initialize logging
logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

# Global variables
valid_tokens = []

default_iss = 'wazuh'
default_aud = 'Wazuh Agent comms API'
GLOBAL_AGENTS_PUBLIC_KEY = 'testing'
default_expiration_time = 900

global database_path

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.path.exists(database_path):
        raise ValueError(f"Directory {database_path} does not exist")

    print(f"Database directory set to: {database_path}")

    yield


app = FastAPI(
    lifespan=lifespan
)


def connect_db():
    global database_path
    return sqlite3.connect(database_path)


app = FastAPI(
    lifespan=lifespan
)

async def get_token(authorization: Optional[str] = Header(None)) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or malformed")

    token = authorization.split(" ")[1]
    # No token validation required for management server mockup
    if token not in valid_tokens:
        raise HTTPException(status_code=403, detail="Invalid JWT token")

    return token


@app.post("/authentication")
async def authenticate(data: AuthData):
    timestamp = int(datetime.now().timestamp())
    iat = timestamp + default_expiration_time
    token = TokenManager.generate_token(default_iss, default_aud, timestamp, iat, data.user)
    valid_tokens.append(token)

    return JSONResponse(content={'token': token})


@app.post("/agents")
async def agents(data: AgentData, authorization: str = Depends(get_token)):
    if not data:
        raise HTTPException(status_code=400, detail="No input data provided")

    uuid = data.uuid
    key = data.key
    name = data.name

    if not uuid or not key or not key or not name:
        raise HTTPException(status_code=400, detail="Missing parameters!")

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM agents WHERE name = "{name}"')
    existing_agent = cursor.fetchone()

    if existing_agent:
        conn.close()
        return JSONResponse(status_code=409, content={'error': 'Agent with this credential already registered', 'uuid': existing_agent[1]})

    cursor.execute('''
        INSERT INTO agents (uuid, credential, name)
        VALUES (?, ?)
    ''', (uuid, key, name))
    conn.commit()
    conn.close()

    return JSONResponse(content={'message': 'Agent was correctly registered'})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')
    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory', dest="database_path")
    parser.add_argument('--key', type=str, required=True, help='Port', dest="key")
    parser.add_argument('--cert', type=str, required=True, help='Port', dest="cert")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")

    args = parser.parse_args()

    global database_path
    database_path = args.database_path

    uvicorn.run(app, host='0.0.0.0', port=args.port, ssl_keyfile=args.key, ssl_certfile=args.cert)