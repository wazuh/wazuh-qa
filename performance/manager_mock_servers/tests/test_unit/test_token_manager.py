# test_token_manager.py

import pytest
from datetime import datetime, timedelta
from fastapi import HTTPException
from manager_mock_servers.utils.token_manager import TokenManager

@pytest.fixture
def token_data():
    return {
        'iss': "test_issuer",
        'aud': "test_audience",
        'iat': int(datetime.now().timestamp()),
        'exp': int((datetime.now() + timedelta(hours=1)).timestamp()),
        'uuid': "test_uuid",
        'credential': "test_secret"
    }

def test_generate_token(token_data):
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], token_data['iat'], token_data['exp'],
        token_data['uuid'], token_data['credential']
    )
    assert isinstance(token, str)

def test_decode_token(token_data):
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], token_data['iat'], token_data['exp'],
        token_data['uuid'], token_data['credential']
    )
    print(token_data)

    decoded_token = TokenManager.decode_token(
        token, token_data['iss'], token_data['aud'], token_data['credential']
    )
    assert decoded_token['iss'] == token_data['iss']
    assert decoded_token['aud'] == token_data['aud']
    assert decoded_token['iat'] == token_data['iat']
    assert decoded_token['exp'] == token_data['exp']
    assert decoded_token['uuid'] == token_data['uuid']

def test_decode_token_expired(token_data):
    expired_iat = int((datetime.utcnow() - timedelta(hours=2)).timestamp())
    expired_exp = int((datetime.utcnow() - timedelta(hours=1)).timestamp())
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], expired_iat, expired_exp,
        token_data['uuid'], token_data['credential']
    )

    with pytest.raises(HTTPException) as exc_info:
        TokenManager.decode_token(token, token_data['iss'], token_data['aud'], token_data['credential'])

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token has expired"

def test_decode_token_invalid(token_data):
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], token_data['iat'], token_data['exp'],
        token_data['uuid'], token_data['credential']
    )
    invalid_secret = "invalid_secret"

    with pytest.raises(HTTPException) as exc_info:
        TokenManager.decode_token(token, token_data['iss'], token_data['aud'], invalid_secret)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"
