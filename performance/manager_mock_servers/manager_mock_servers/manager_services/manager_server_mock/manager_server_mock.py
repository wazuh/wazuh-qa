"""Testing."""
import argparse
import logging
import os
import secrets
import sqlite3
import string
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from manager_mock_servers.manager_services.manager_server_mock.models import AgentData, AuthData, TokenManager
from manager_mock_servers.utils.vars import DEFAULT_AUD, DEFAULT_EXPIRATION_TIME, DEFAULT_ISS

# Initialize logging
logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.INFO)

global DATABASE_PATH
VALID_TOKENS = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Testing."""
    if not os.path.exists(DATABASE_PATH):
        raise ValueError(f"Directory {DATABASE_PATH} does not exist")

    yield

def generate_random_string(length=32):
    """Testing."""
    characters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(secrets.choice(characters) for _ in range(length))

    return random_string


async def get_token(authorization: Optional[str] = Header(None)) -> str:
    """Testing."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or malformed")

    token = authorization.split(" ")[1]
    # No token validation required for management server mockup
    if token not in VALID_TOKENS:
        raise HTTPException(status_code=403, detail="Invalid JWT token")

    return token


def check_if_agent_exists(agent_name):
    """Testing."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM agents WHERE name = "{agent_name}"')
    existing_agent = cursor.fetchone()
    conn.close()

    return existing_agent

def insert_new_agent(uuid, key, name):
    """Testing."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO agents (uuid, credential, name)
        VALUES (?, ?, ?)
    ''', (uuid, key, name))
    conn.commit()
    conn.close()


def start_server_manager(application, database_path, port, ssl_keyfile, ssl_certfile):
    """Testing."""
    set_database_path(database_path)
    uvicorn.run(application, host='0.0.0.0', port=port, ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile)


def set_database_path(db_path):
    """Testing."""
    global DATABASE_PATH
    DATABASE_PATH = db_path


app = FastAPI(
    lifespan=lifespan
)

@app.post("/authentication")
async def authenticate(data: AuthData):
    """Testing."""
    timestamp = int(datetime.now().timestamp())
    exp = timestamp + DEFAULT_EXPIRATION_TIME

    token = TokenManager.generate_token(DEFAULT_ISS, DEFAULT_AUD, timestamp, exp,
                                        data.user, generate_random_string(10))
    VALID_TOKENS.append(token)

    return JSONResponse(content={'token': token})


@app.post("/agents")
async def agents(data: AgentData, authorization: str = Depends(get_token)):
    """Testing."""
    if not data:
        raise HTTPException(status_code=400, detail="No input data provided")

    uuid, key, name = data.uuid, data.key, data.name

    if not uuid or not key or not key or not name:
        raise HTTPException(status_code=400, detail="Missing parameters!")

    existing_agent = check_if_agent_exists(name)

    if existing_agent:
        return JSONResponse(status_code=409, content={'error': 'Agent with this credential already registered',
                                                      'uuid': existing_agent[1]})
    insert_new_agent(uuid, key, name)

    return JSONResponse(content={'message': 'Agent was correctly registered'})


def main():
    """Testing."""
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')
    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory',
                        dest="database_path")
    parser.add_argument('--key', type=str, required=True, help='Port', dest="key")
    parser.add_argument('--cert', type=str, required=True, help='Port', dest="cert")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")

    args = parser.parse_args()

    start_server_manager(app, args.database_path, args.port, args.key, args.cert)


if __name__ == "__main__":
    main()
