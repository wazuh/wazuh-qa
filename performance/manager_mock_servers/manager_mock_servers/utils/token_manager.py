"""Testing."""

import jwt
from fastapi import HTTPException


class TokenManager:
    """Testing."""
    @staticmethod
    def generate_token(iss: str, aud: str, iat: int, exp: int, uuid: str, credential: str) -> str:
        """Testing."""
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
    def decode_token(token, issuer, audience, secret_key):
        """Testing."""
        try:
            decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"],
                                       audience=audience, issuer=issuer)
        except jwt.ExpiredSignatureError as expired_error:
            raise HTTPException(status_code=401, detail="Token has expired") from expired_error
        except jwt.InvalidTokenError as invalid_error:
            raise HTTPException(status_code=401, detail="Invalid token") from invalid_error

        return decoded_token
