# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""This module provides the `TokenManager` class for generating and decoding JSON Web Tokens (JWTs).

Classes
    TokenManager: A class that handles the creation and validation of JWTs.
"""
import jwt
from fastapi import HTTPException


class TokenManager:
    """A class to manage JSON Web Tokens (JWT) including generation and decoding."""
    @staticmethod
    def generate_token(iss: str, aud: str, iat: int, exp: int, uuid: str, credential: str) -> str:
        """Generates a JWT token with the given payload and secret key.

        Args:
            iss (str): The issuer of the token.
            aud (str): The audience of the token.
            iat (int): The issued at time (timestamp).
            exp (int): The expiration time (timestamp).
            uuid (str): The unique identifier for the token.
            credential (str): The secret key used to sign the token.

        Returns:
            str: The encoded JWT token.
        """
        payload = {
            'iss': iss,
            'aud': aud,
            'iat': iat,
            'exp': exp,
            'uuid': uuid
        }
        token = jwt.encode(payload, credential, algorithm='HS256')
        return token

    @staticmethod
    def decode_token(token: str, issuer: str, audience: str, secret_key: str) -> dict:
        """Decodes a JWT token and validates its claims against the provided issuer, audience, and secret key.

        Args:
            token (str): The JWT token to decode.
            issuer (str): The expected issuer of the token.
            audience (str): The expected audience of the token.
            secret_key (str): The secret key used to decode the token.

        Returns:
            dict: The decoded token payload.

        Raises:
            HTTPException: If the token has expired or is invalid.
        """

        try:
            decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"],
                                       audience=audience, issuer=issuer)
        except jwt.ExpiredSignatureError as expired_error:
            raise HTTPException(status_code=401, detail="Token has expired") from expired_error
        except jwt.InvalidTokenError as invalid_error:
            raise HTTPException(status_code=401, detail="Invalid token") from invalid_error

        return decoded_token
