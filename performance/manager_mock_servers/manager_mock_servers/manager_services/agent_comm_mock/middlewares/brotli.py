"""Module for Brotli compression middleware in a FastAPI application.

This module defines the `BrotliMiddleware` class, which is a custom middleware for compressing HTTP responses
using Brotli compression. It checks if the client supports Brotli (indicated by the 'accept-encoding' header
containing 'br') and compresses the response body if the response status code is 200.
"""
import brotli
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class BrotliMiddleware(BaseHTTPMiddleware):
    """Middleware to compress HTTP responses using Brotli compression if the client supports it.

    This middleware checks if the incoming request's 'accept-encoding' header includes 'br' (Brotli).
    If so, and if the response status code is 200, it compresses the response body using Brotli
    compression and updates the response headers to reflect the encoding.

    Methods:
        dispatch(request: Request, call_next) -> Response:
            Processes the incoming request and response, applying Brotli compression if applicable.

    Args:
        request (Request): The incoming HTTP request.
        call_next (Callable): The next function to call in the request chain, which returns the response.

    Returns:
        Response: The HTTP response, potentially with Brotli compression applied.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if 'accept-encoding' in request.headers and 'br' in request.headers['accept-encoding']:
            if response.status_code == 200:
                content = response.body
                compressed_content = brotli.compress(content)
                headers = dict(response.headers)
                headers['Content-Encoding'] = 'br'
                headers['Content-Length'] = str(len(compressed_content))
                return Response(content=compressed_content, headers=headers, status_code=response.status_code)
        return response

