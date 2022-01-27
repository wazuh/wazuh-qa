import random

import wazuh_testing


def add_client_keys_entry(agent_id, agent_name, agent_ip='any', agent_key=None):
    """Add new entry to client keys file. If the agent_id already exists, this will be overwritten.

    Args:
        agent_id (str): Agent identifier.
        agent_name (str): Agent name.
        agent_ip (str): Agent ip.
        agent_key (str): Agent key.
    """
    registered_client_key_entries_dict = {}

    # Generate new key if necessary
    if agent_key is None:
        agent_key = ''.join(random.choice('0123456789abcdef') for i in range(64))

    # Read client keys data
    with open(wazuh_testing.CLIENT_KEYS_PATH, 'r') as client_keys:
        registered_client_key_entries_str = client_keys.readlines()

    # Process current client key entries
    for client_key_entry in registered_client_key_entries_str:
        _agent_id, _agent_name, _agent_ip, _agent_key = client_key_entry.split()
        registered_client_key_entries_dict[_agent_id] = f"{_agent_id} {_agent_name} {_agent_ip} {_agent_key}"

    # Add the new client key entry
    registered_client_key_entries_dict[agent_id] = f"{agent_id} {agent_name} {agent_ip} {agent_key}"

    # Save new client keys content
    with open(wazuh_testing.CLIENT_KEYS_PATH, 'w') as client_keys:
        for _, client_key_entry in registered_client_key_entries_dict.items():
            client_keys.write(f"{client_key_entry}\n")


def delete_client_keys_entry(agent_id):
    """Delete an entry from client keys file.

    Args:
        agent_id (str): Agent identifier.
    """
    registered_client_key_entries_dict = {}

    # Read client keys data
    with open(wazuh_testing.CLIENT_KEYS_PATH, 'r') as client_keys:
        registered_client_key_entries_str = client_keys.readlines()

    # Process current client key entries
    for client_key_entry in registered_client_key_entries_str:
        _agent_id, _agent_name, _agent_ip, _agent_key = client_key_entry.split()
        registered_client_key_entries_dict[_agent_id] = f"{_agent_id} {_agent_name} {_agent_ip} {_agent_key}"

    # Remove client key entry
    registered_client_key_entries_dict.pop(agent_id, None)

    # Save new client keys content
    with open(wazuh_testing.CLIENT_KEYS_PATH, 'w') as client_keys:
        for _, client_key_entry in registered_client_key_entries_dict.items():
            client_keys.write(f"{client_key_entry}\n")
