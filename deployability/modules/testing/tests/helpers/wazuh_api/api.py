from datetime import datetime, timedelta
import requests

from .exceptions import wazuh_api_exceptions


class WazuhAPI:

    def __init__(self, user: str, password: str, host: str = 'localhost', port: int = 55000):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        # Token default values
        self.token = None
        self.token_lifetime = 900
        self.token_expiration = None
        # Authenticate and save the token value and expiration
        self.authenticate()

    def authenticate(self) -> str:
        endpoint = self._get_complete_url('security/user/authenticate')
        credentials = {'user': self.user, 'password': self.password}
        # _send_request is not used here because of the auth parameter.
        response = requests.post(endpoint, auth=credentials)
        if response.status_code in wazuh_api_exceptions.keys():
            raise wazuh_api_exceptions[response.status_code]
        self.token_expiration = datetime.now() + timedelta(seconds=self.token_lifetime)
        self.token = response.json()['data']['token']

    def extend_token_life(self, timeout: int = 99999999) -> dict:
        endpoint = self._get_complete_url('security/config')
        data = {"auth_token_exp_timeout": timeout, "rbac_mode": "white"}
        response = self._send_request('put', endpoint, data=data)
        self.token_lifetime = timeout
        return response

    def _send_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        if not self.token:
            self.authenticate()
        elif self.token_expiration <= datetime.now():
            self.authenticate()
        # Set the headers and send the request
        headers = {'Authorization': f'Bearer {self.token}'}
        response = requests.request(method, endpoint, data=data, headers=headers)
        # Check if the response is an error
        if response.status_code in wazuh_api_exceptions.keys():
            print(f'Failing request to: {endpoint}\nError: {response.content}')
            raise wazuh_api_exceptions[response.status_code]
        return response.json()

    def _get_complete_url(self, endpoint) -> str:
        if endpoint.startswith('/'):
            endpoint = endpoint[1:]
        return f'https://{self.host}:{self.port}/{endpoint}'
