# Test that agent-files are deleted after unregistering agents
## Overview
This test checks that, when an agent is removed/unregistered, the files related to it that exist on the master and worker nodes are removed. Those files are:

- `{wazuh_path}/queue/diff/{name}`
- `{wazuh_path}/queue/agent-groups/{id}`
- `{wazuh_path}/queue/rids/{id}`
- `{wazuh_path}/var/db/agents/{name}-{id}.db`
- `{wazuh_path}/queue/db/{id}.db`

It is also verified that the information related to the unregistered agent is deleted from the following tables (inside `global.db`):

- agent
- belongs

## Objective

To confirm that no remaining files are left in the managers after deleting registered agents.

## General info

| Number of tests | Time spent |
|:--|:--:|
| 1 | 106s |

## Expected behavior

- Fail if any of the agent files cannot be found when it has not been unregistered yet.
- Fail if there is no information of the agent in `global.db` when it has not been unregistered yet.
- Fail if after unregistering the agent, any of the expected files are not removed.
- Fail if after unregistering the agent, any of the expected information in `global.db` can be queried.

## Code documentation

::: tests.system.test_cluster.test_agent_files_deletion.test_agent_files_deletion
