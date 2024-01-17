import requests

from datetime import datetime, timedelta

from .exceptions import responses_errors
from . import endpoints


class WazuhAPI:

    def __init__(self, user: str, password: str, host: str = 'localhost', port: int = 55000) -> None:
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        # Create a requests session and disable the warnings
        self.session = requests.Session()
        requests.packages.urllib3.disable_warnings()
        # Token default values
        self.token = None
        self.token_lifetime = 900
        self.token_expiration = None
        # Authenticate and save the token value and expiration
        self.authenticate()

    # Security

    def authenticate(self) -> str:
        endpoint = self._get_complete_url(endpoints.SECURITY_AUTHENTICATE)
        credentials = (self.user, self.password)
        # _send_request is not used here because of the auth parameter.
        response = self.session.get(endpoint, auth=credentials, verify=False)
        if response.status_code in responses_errors.keys():
            print(f'Authentication error: {response.content}')
            raise responses_errors[response.status_code]
        self.token_expiration = datetime.now() + timedelta(seconds=self.token_lifetime)
        self.token = response.json()['data']['token']

    def extend_token_life(self, timeout: int = 99999999) -> dict:
        endpoint = self._get_complete_url(endpoints.SECURITY_CONFIG)
        payload = {"auth_token_exp_timeout": timeout, "rbac_mode": "white"}
        response = self._send_request('put', endpoint, payload=payload)
        self.token_lifetime = timeout
        return response

    # Agents

    def add_agent(self, name: str, ip: str) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        payload = {'name': name, 'ip': ip}
        return self._send_request('post', endpoint, payload=payload)

    def get_agent(self, agent_id: str) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {'agents_list': [agent_id]}
        return self._send_request('get', endpoint, query_params=params)

    def get_agents(self, agents_ids: list[str],  **kwargs: dict) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {**kwargs, 'agents_list': agents_ids}
        return self._send_request('get', endpoint, query_params=params)

    def delete_agent(self, agent_id: str) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {'agents_list': [agent_id], 'status': 'all'}
        return self._send_request('delete', endpoint, query_params=params)

    def delete_agents(self, agents_ids: list, **kwargs: dict) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {**kwargs, 'agents_list': agents_ids}
        return self._send_request('delete', endpoint, query_params=params)

    # --- INTERNAL METHODS ---

    def _send_request(self, method: str, endpoint: str, payload: dict = None, query_params: dict = {}) -> dict:
        if not self.token:
            self.authenticate()
        elif self.token_expiration <= datetime.now():
            self.authenticate()
        # Set the headers and send the request
        headers = {'Authorization': f'Bearer {self.token}'}
        query_params['pretty'] = 'true'
        response = self.session.request(
            method, endpoint, data=payload, headers=headers, params=query_params, verify=False)
        # Check if the response is an error
        if response.status_code in responses_errors.keys():
            print(f'Failing request to: {endpoint}\nError: {response.content}')
            raise responses_errors[response.status_code]
        return response.json()

    def _get_complete_url(self, endpoint) -> str:
        if endpoint.startswith('/'):
            endpoint = endpoint[1:]
        return f'https://{self.host}:{self.port}/{endpoint}'
