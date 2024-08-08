import pytest
from datetime import datetime, timedelta
from fastapi import HTTPException
from manager_mock_servers.utils.token_manager import TokenManager

@pytest.fixture
def token_data():
    """
    Fixture that provides a dictionary of token data for testing.

    This fixture generates and returns a dictionary containing the necessary data
    to create and verify tokens. The dictionary includes issuer, audience, issue time,
    expiration time, UUID, and a credential.

    Returns:
        dict: A dictionary with keys 'iss', 'aud', 'iat', 'exp', 'uuid', and 'credential',
              representing the data used to generate and verify tokens.
    """
    return {
        'iss': "test_issuer",
        'aud': "test_audience",
        'iat': int(datetime.now().timestamp()),
        'exp': int((datetime.now() + timedelta(hours=1)).timestamp()),
        'uuid': "test_uuid",
        'credential': "test_secret"
    }

def test_generate_token(token_data):
    """
    Test that the `generate_token` method creates a token of type string.

    This test verifies that the `TokenManager.generate_token` method returns a string
    when provided with valid token data. It does not check the content of the token,
    only that it is of the correct type.

    Args:
        token_data (dict): Dictionary of token data provided by the fixture.

    Assertions:
        Asserts that the generated token is a string.
    """
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], token_data['iat'], token_data['exp'],
        token_data['uuid'], token_data['credential']
    )
    assert isinstance(token, str)

def test_decode_token(token_data):
    """
    Test that the `decode_token` method correctly decodes a valid token.

    This test checks that the `TokenManager.decode_token` method can decode a token
    generated with the `TokenManager.generate_token` method, and that the decoded
    data matches the original token data.

    Args:
        token_data (dict): Dictionary of token data provided by the fixture.

    Assertions:
        Asserts that the decoded token's fields match the original token data fields.
    """
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], token_data['iat'], token_data['exp'],
        token_data['uuid'], token_data['credential']
    )

    decoded_token = TokenManager.decode_token(
        token, token_data['iss'], token_data['aud'], token_data['credential']
    )
    assert decoded_token['iss'] == token_data['iss']
    assert decoded_token['aud'] == token_data['aud']
    assert decoded_token['iat'] == token_data['iat']
    assert decoded_token['exp'] == token_data['exp']
    assert decoded_token['uuid'] == token_data['uuid']

def test_decode_token_expired(token_data):
    """
    Test that the `decode_token` method raises an HTTPException for an expired token.

    This test checks that the `TokenManager.decode_token` method raises an HTTPException
    with a 401 status code and the message "Token has expired" when attempting to decode
    a token that has expired.

    Args:
        token_data (dict): Dictionary of token data provided by the fixture.

    Assertions:
        Asserts that decoding an expired token raises an HTTPException with the correct status code
        and detail message.
    """
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
    """
    Test that the `decode_token` method raises an HTTPException for a token with an invalid secret.

    This test verifies that the `TokenManager.decode_token` method raises an HTTPException
    with a 401 status code and the message "Invalid token" when decoding a token using
    an incorrect secret.

    Args:
        token_data (dict): Dictionary of token data provided by the fixture.

    Assertions:
        Asserts that decoding a token with an invalid secret raises an HTTPException with the correct status code
        and detail message.
    """
    token = TokenManager.generate_token(
        token_data['iss'], token_data['aud'], token_data['iat'], token_data['exp'],
        token_data['uuid'], token_data['credential']
    )
    invalid_secret = "invalid_secret"

    with pytest.raises(HTTPException) as exc_info:
        TokenManager.decode_token(token, token_data['iss'], token_data['aud'], invalid_secret)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"
