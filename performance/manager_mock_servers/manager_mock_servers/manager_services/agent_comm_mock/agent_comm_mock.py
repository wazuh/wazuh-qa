"""Testing.
# class BrotliMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request: Request, call_next):
#         response = await call_next(request)
#         if 'accept-encoding' in request.headers and 'br' in request.headers['accept-encoding']:
#             if response.status_code == 200:
#                 content = response.body
#                 compressed_content = brotli.compress(content)
#                 headers = dict(response.headers)
#                 headers['Content-Encoding'] = 'br'
#                 headers['Content-Length'] = str(len(compressed_content))
#                 return Response(content=compressed_content, headers=headers, status_code=response.status_code)
#         return response.
"""
import argparse
import asyncio
import datetime
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import Optional

import jwt
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from manager_mock_servers.manager_services.agent_comm_mock.models import AuthRequest, StatefullData, StatelessEvent
from manager_mock_servers.utils.vars import DEFAULT_AUD, DEFAULT_ISS, DEFAULT_EXPIRATION_TIME, MANAGER_MOCK_TOKEN_SECRET_KEY
from manager_mock_servers.utils.token_manager import TokenManager

global database_directory

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)


def set_database_path(db_path):
    global database_directory
    database_directory = db_path


@asynccontextmanager
async def lifespan(app: FastAPI):
    global database_directory
    if not os.path.exists(database_directory):
        raise ValueError(f"Directory {database_directory} does not exist")

    logging.error(f"Database directory set to: {database_directory}")

    yield

app = FastAPI(
    lifespan=lifespan
)


async def get_token(authorization: Optional[str] = Header(None)) -> str:
    """Testing."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or malformed")
    try:
        token = authorization.split(" ")[1]
        TokenManager.decode_token(token, DEFAULT_ISS, DEFAULT_AUD, MANAGER_MOCK_TOKEN_SECRET_KEY)
    except Exception as decode_token_error:
        raise HTTPException(status_code=401, detail="Token has expired") from decode_token_error

    return token


def connect_db():
    """Testing."""
    global database_directory
    return sqlite3.connect(database_directory)


@app.post('/authentication')
async def authenticate(auth_request: AuthRequest):
    """Testing."""
    user_id = auth_request.uuid
    key = auth_request.key

    conn = connect_db()
    logger.error(database_directory)
    cursor = conn.cursor()

    cursor.execute(f'SELECT * FROM agents WHERE uuid = "{user_id}"')
    existing_agent = cursor.fetchone()
    cursor.execute(f'SELECT credential FROM agents WHERE uuid = "{user_id}"')
    credential = cursor.fetchone()

    conn.commit()
    conn.close()

    if not existing_agent:
        return JSONResponse(status_code=409, content={'message': 'Agent with uuid does not exists'})
    if key != credential:
        return JSONResponse(status_code=409, content={'message': 'Invalid Key provided'})

    timestamp = int(datetime.datetime.now().timestamp())

    iat = timestamp
    exp = timestamp + DEFAULT_EXPIRATION_TIME
    token = TokenManager.generate_token(DEFAULT_ISS, DEFAULT_AUD, iat, exp, user_id, credential)

    return JSONResponse(content={'token': token})


@app.post('/events/stateless')
async def stateless_event(event: StatelessEvent, authorization: str = Depends(get_token)):
    """Testing. TODO include logic to count events."""
    return {'message': 'Event received'}


@app.post('/events/stateful')
async def stateful_event(event: StatefullData, authorization: str = Depends(get_token)):
    """Testing."""
    return {'message': 'Event is being processed and will be persisted'}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')
    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory',
                        dest="database_path")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")
    parser.add_argument('--cert', type=str, required=True, help='Port', dest="cert")
    parser.add_argument('--key', type=str, required=True, help='Port', dest="key")

    args = parser.parse_args()

    global database_directory

    database_directory = args.database_path
    uvicorn.run(app, host='0.0.0.0', port=args.port, ssl_keyfile=args.key, ssl_certfile=args.cert)
