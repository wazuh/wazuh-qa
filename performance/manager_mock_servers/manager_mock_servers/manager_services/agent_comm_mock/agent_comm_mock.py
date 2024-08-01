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
from manager_mock_servers.utils.vars import DEFAULT_AUD, DEFAULT_ISS, DEFAULT_EXPIRATION_TIME

global database_directory

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

# uuid - token
valid_tokens = {}


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
#         return response


def set_database_path(db_path):
    global database_directory
    database_directory = db_path


def get_token_secret_key(token):
    secret_key = ''
    for t in valid_tokens.keys():
        logger.debug(token)
        logger.debug(t)
        if token == token:
            conn = connect_db()
            cursor = conn.cursor()
            agent, exp = valid_tokens[t]
            cursor.execute(f'SELECT credential FROM agents WHERE uuid = "{agent}"')
            secret_key = cursor.fetchone()[0]

    logger.debug(secret_key)

    return secret_key

@asynccontextmanager
async def lifespan(app: FastAPI):
    global database_directory
    if not os.path.exists(database_directory):
        raise ValueError(f"Directory {database_directory} does not exist")

    logging.error(f"Database directory set to: {database_directory}")

    loop = asyncio.get_event_loop()
    loop.create_task(remove_expired_tokens())

    yield

app = FastAPI(
    lifespan=lifespan
)

async def remove_expired_tokens():
    while True:
        current_time = int(datetime.datetime.now().timestamp())
        outdated_tokens = [token for token in valid_tokens.keys() if valid_tokens[token][1] >= current_time]
        for token in outdated_tokens:
            del valid_tokens[token]
        await asyncio.sleep(60)  # Check every 60 seconds



class TokenManager:
    @staticmethod
    def generate_token(iss: str, aud: str, iat: int, exp: int, uuid: str, credential: str) -> str:
        payload = {
            'iss': iss,
            'aud': aud,
            'iat': iat,
            'exp': exp,
            'uuid': uuid
        }
        token = jwt.encode(payload, credential, algorithm='HS256')
        return token

async def get_token(authorization: Optional[str] = Header(None)) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or malformed")

    token = authorization.split(" ")[1]

    try:
        secret_key = get_token_secret_key(token)
        # Decode the token
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"], audience=DEFAULT_AUD, issuer=DEFAULT_ISS)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return token

def get_token_secret_key(token: str) -> str:
    secret_key = ''
    for t in valid_tokens.keys():
        if token == t:
            conn = connect_db()
            cursor = conn.cursor()
            agent, exp = valid_tokens[t]
            cursor.execute(f'SELECT credential FROM agents WHERE uuid = "{agent}"')
            secret_key = cursor.fetchone()[0]
            conn.close()
    logger.debug(secret_key)
    return secret_key


def connect_db():
    global database_directory
    return sqlite3.connect(database_directory)


@app.post('/authentication')
async def authenticate(auth_request: AuthRequest):
    # Extract data from the request model
    user_id = auth_request.uuid
    key = auth_request.key

    # Get agent credentials
    conn = connect_db()
    logger.error(database_directory)
    cursor = conn.cursor()

    cursor.execute(f'SELECT * FROM agents WHERE uuid = "{user_id}"')
    cursor.execute(f'SELECT credential FROM agents WHERE uuid = "{user_id}"')
    existing_agent = cursor.fetchone()
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

    valid_tokens[token] = (user_id, exp)

    return JSONResponse(content={'token': token})


@app.post('/events/stateless')
async def stateless_event(event: StatelessEvent, authorization: str = Depends(get_token)):
    logger.debug(event.events[0])
    return {'message': 'Event received'}


@app.post('/events/stateful')
async def stateful_event(event: StatefullData, authorization: str = Depends(get_token)):
    return {'message': 'Event is being processed and will be persisted'}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start FastAPI with database path')
    parser.add_argument('--database-path', type=str, required=True, help='Path to the database directory', dest="database_path")
    parser.add_argument('--port', type=int, required=True, help='Port', dest="port")
    parser.add_argument('--cert', type=str, required=True, help='Port', dest="cert")
    parser.add_argument('--key', type=str, required=True, help='Port', dest="key")

    args = parser.parse_args()

    global database_directory


    database_directory = args.database_path
    uvicorn.run(app, host='0.0.0.0', port=args.port, ssl_keyfile=args.key, ssl_certfile=args.cert)
