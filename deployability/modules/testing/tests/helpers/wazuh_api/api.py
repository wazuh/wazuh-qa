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
        # Token default values
        self.token = None
        self.token_lifetime = 900
        self.token_expiration = None
        # Create a requests session and disable the warnings
        self.session = requests.Session()
        requests.packages.urllib3.disable_warnings()
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

    # API Info

    def get_api_info(self) -> dict:
        endpoint = self._get_complete_url(endpoints.API_ROOT)
        return self._send_request('get', endpoint)

    # Agents

    def add_agent(self, name: str, ip: str) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        payload = {'name': name, 'ip': ip}
        return self._send_request('post', endpoint, payload=payload)

    def get_agent(self, agent_id: str) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {'agents_list': [agent_id]}
        return self._send_request('get', endpoint, query_params=params)

    def get_agents(self, **kwargs: dict) -> list[dict]:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        return self._send_request('get', endpoint, query_params=kwargs)

    def delete_agent(self, agent_id: str) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {'agents_list': [agent_id], 'status': 'all'}
        return self._send_request('delete', endpoint, query_params=params)

    def delete_agents(self, agents_list: list, **kwargs: dict) -> dict:
        endpoint = self._get_complete_url(endpoints.AGENTS)
        params = {**kwargs, 'agents_list': agents_list}
        return self._send_request('delete', endpoint, query_params=params)

    # Manager

    def get_manager_status(self) -> dict:
        endpoint = self._get_complete_url(endpoints.MANAGER_STATUS)
        return self._send_request('get', endpoint)

    def get_manager_info(self) -> dict:
        endpoint = self._get_complete_url(endpoints.MANAGER_INFO)
        return self._send_request('get', endpoint)

    def get_manager_configuration(self) -> dict:
        endpoint = self._get_complete_url(endpoints.MANAGER_CONFIGURATION)
        return self._send_request('get', endpoint)

    # Cluster

    def get_cluster_nodes(self) -> dict:
        endpoint = self._get_complete_url(endpoints.CLUSTER_NODES)
        return self._send_request('get', endpoint)

    def get_cluster_local_node(self) -> dict:
        endpoint = self._get_complete_url(endpoints.CLUSTER_LOCAL_NODE)
        return self._send_request('get', endpoint)

    def get_cluster_local_node_info(self) -> dict:
        endpoint = self._get_complete_url(endpoints.CLUSTER_LOCAL_NODE_INFO)
        return self._send_request('get', endpoint)

    def get_cluster_healthcheck(self) -> dict:
        endpoint = self._get_complete_url(endpoints.CLUSTER_HEALTHCHECK)
        return self._send_request('get', endpoint)

    def get_cluster_status(self) -> dict:
        endpoint = self._get_complete_url(endpoints.CLUSTER_STATUS)
        return self._send_request('get', endpoint)

    def get_cluster_node_status(self, node_id: str) -> dict:
        endpoint = self._get_complete_url(
            endpoints.CLUSTER_NODE_STATUS.substitute(node_id=node_id))
        return self._send_request('get', endpoint)

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
        # In add agent the response is different
        data = response.json().get('data', {})
        if items := data.get('affected_items'):
            return items if len(items) > 1 else items[0]
        return data

    def _get_complete_url(self, endpoint: str = '/') -> str:
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        return f'https://{self.host}:{self.port}{endpoint}'
