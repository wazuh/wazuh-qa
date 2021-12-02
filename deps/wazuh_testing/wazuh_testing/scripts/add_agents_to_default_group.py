import os
import sys

from wazuh_testing.tools import CLIENT_KEYS_PATH


def main():
    if len(sys.argv) != 3:
        print(f"add_agents_to_default_group.py <first_id> <last_id> (you used {' '.join(sys.argv)})")
        exit(1)

    first_id = min(int(sys.argv[1]), int(sys.argv[2]))
    last_id = max(int(sys.argv[1]), int(sys.argv[2]))

    agents_list = [str(agent_id).zfill(3) for agent_id in range(first_id, last_id + 1)]

    with open(file=CLIENT_KEYS_PATH, mode='r') as f:
        agents_in_client_keys = f.read().split('\n')[:-1]
    available_agents = [agent.split()[0] for agent in agents_in_client_keys]

    for agent_id in set(agents_list).intersection(available_agents):
        agent_group_file = f"/var/ossec/queue/agent-groups/{agent_id}"
        if not os.path.exists(agent_group_file):
            with open(file=agent_group_file, mode='w') as f:
                f.write('default')

    exit(0)


if __name__ == '__main__':
    main()
