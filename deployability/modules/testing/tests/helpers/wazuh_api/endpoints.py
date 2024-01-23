#   - Wazuh API endpoints

# -- Root --
from string import Template


API_ROOT = '/'

# -- Security --
SECURITY = '/security'
# Users
SECURITY_USER = f'{SECURITY}/user'
SECURITY_USERS = f'{SECURITY}/users'
# Authentication
SECURITY_AUTHENTICATE = f'{SECURITY_USER}/authenticate'
# Configuration
SECURITY_CONFIG = f'{SECURITY}/config'

# -- Groups --
GROUPS = '/groups'

# -- Agents --
AGENTS = '/agents'
AGENTS_GROUP = f'{AGENTS}/group'

# -- Cluster --
CLUSTER = '/cluster'
CLUSTER_NODES = f'{CLUSTER}/nodes'
CLUSTER_LOCAL_NODE = f'{CLUSTER}/local_node'
CLUSTER_LOCAL_NODE_INFO = f'{CLUSTER_LOCAL_NODE}/info'
CLUSTER_HEALTHCHECK = f'{CLUSTER}/healthcheck'
CLUSTER_STATUS = f'{CLUSTER}/status'
CLUSTER_NODE_STATUS = Template(f'{CLUSTER}/$node_id/status')

# -- Manager --
MANAGER = '/manager'
MANAGER_STATUS = f'{MANAGER}/status'
MANAGER_INFO = f'{MANAGER}/info'
MANAGER_CONFIGURATION = f'{MANAGER}/configuration'