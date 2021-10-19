#!/usr/bin/env python

import json
import sys

keys_db = [
    {
        # Agent 001 basic configuration
        'id': '001',
        'ip': 'any',
        'name': 'wazuh-agent1',
        'key': '1111111111111111111111111111111111111111111111111111111111111111'
    },
    {
        # Agent 002 basic configuration
        'id': '002',
        'ip': 'any',
        'name': 'wazuh-agent2',
        'key': '2222222222222222222222222222222222222222222222222222222222222222'
    },
    {
        # Agent 003 basic configuration
        'id': '003',
        'ip': 'any',
        'name': 'wazuh-agent3',
        'key': '3333333333333333333333333333333333333333333333333333333333333333'
    }
]


def main():
    """This file regenerate the agent key after a manipulation of it
    Print the legacy key of the agent, this way the agent key polling module can set the correct key again.

    """
    if len(sys.argv) < 3:
        print(json.dumps({"error": 1, "message": "Too few arguments"}))
        return

    try:
        value = sys.argv[2]
        data = list(
            (filter(lambda agent: agent[sys.argv[1]] == value, keys_db)))
        if len(data) == 1:
            print(json.dumps({"error": 0, "data": data[0]}))
        elif len(data) > 1:
            print(json.dumps(
                {"error": 5, "message": f"Found more than one match for required {sys.argv[1]}"}))
        else:
            print(json.dumps({"error": 4, "message": "No agent key found"}))
    except KeyError:
        print(json.dumps({"error": 3, "message": "Bad arguments given"}))
        return
    except Exception as e:
        print(json.dumps({"error": 2, "message": str(e)}))
        return


if __name__ == '__main__':
    main()
