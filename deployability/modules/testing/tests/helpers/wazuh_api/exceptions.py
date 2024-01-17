from requests import RequestException



class BadRequest(RequestException):
    """A bad request error occurred."""


class Unauthorized(RequestException):
    """An unauthorized error occurred."""


class Forbidden(RequestException):
    """A forbidden error occurred."""


class NotFound(RequestException):
    """A not found error occurred."""


class MethodNotAllowed(RequestException):
    """A method not allowed error occurred."""


class TooManyRequests(RequestException):
    """A request limit exceeded error occurred."""


class InternalServerError(RequestException):
    """An internal server error occurred."""


class ServiceUnavailable(RequestException):
    """A service unavailable error occurred."""


class GatewayTimeout(RequestException):
    """A gateway timeout error occurred."""


wazuh_api_exceptions = {
    400: BadRequest,
    401: Unauthorized,
    403: Forbidden,
    404: NotFound,
    405: MethodNotAllowed,
    429: TooManyRequests,
    500: InternalServerError,
    501: ServiceUnavailable,
    503: GatewayTimeout
}