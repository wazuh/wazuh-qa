import sys

from wazuh_testing.tools import CLIENT_KEYS_PATH


def main():
    """Add fake agents to client.keys. To use the script, pass two arguments indicating the first agent ID and the last
    agent ID from the range of agents to be added.

    The agents added will have ID={agent_id}, name=new_agent_{agent_id}, address=any; and password={agent_id}.

    This script must be used in the Wazuh master node.
    """
    if len(sys.argv) != 3:
        print(f"add_agents_client_keys.py <first_id> <last_id> (you used {' '.join(sys.argv)})")
        exit(1)

    first_id = min(int(sys.argv[1]), int(sys.argv[2]))
    last_id = max(int(sys.argv[1]), int(sys.argv[2]))

    agents_list = [str(agent_id).zfill(3) for agent_id in range(first_id, last_id + 1)]

    with open(file=CLIENT_KEYS_PATH, mode='a') as f:
        for agent_id in agents_list:
            f.write(f"{agent_id} new_agent_{agent_id} any {agent_id}\n")
            f.flush()  # Avoid bytes staying in the buffer until the loop has finished
    exit(0)


if __name__ == "__main__":
    main()
