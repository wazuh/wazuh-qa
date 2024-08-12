## Manager Service mocks

This package provides scripts and tools to simulate the Agent Communication and Management Server API services of the Wazuh manager. These mocks are specifically designed for performance testing of the agent and are not intended for use in a production environment.

### Scripts

- `simulate_manager`: A script to simulate the behavior of the full Wazuh manager. See the script [documentation](manager_mock_servers/README.md) for more details.
- `simulate-management-server`: A mock for the Management Server API services. Refer to the script [documentation](manager_services/manager_server_mock/README.md) for more information.
- `simulate-agent-comm`: A mock for the Agent Communication services. Detailed information is available in the [documentation](manager_services/agent_comm_mock/README.md).


### Usage

To simulate a full manager with agent communication and management API services, you can use the simulate-manager script. This script can be executed with the following command:

```bash
simulate-manager --manager-api-port <management-port> --agent-comm-api-port <agent-comm-port> --server-path </path/to/server> --report-path </path/to/report.csv>
```

This command will initiate the agent communication and management API services on the specified ports, setting up the database in the specified server path. Additionally, all received event data will be logged in the designated report.csv file.

You can also run the mock versions of the agent communication and management API services separately. However, you will need to create SSL credentials to enable HTTPS for these services. Refer to the relevant README files for detailed instructions on setting up SSL credentials.


### Installation

1. Move to the `performance/manager_mock_servers` directory
2. Create the Python environment

```bash
python3 -m venv env
```

3. Activate the environment:
```bash
source env/bin/activate
```

4. Install the package
```bash
python3 -m pip install .
```

### Tests

To run the package tests, follow these steps:


1. Move to the 'performance/manager_mock_servers' directory
2. Create the Python environment

```bash
python3 -m venv testing-env
```

3. Activate the environment:
```bash
source testing-env/bin/activate
```

4. Install the package
```bash
python3 -m pip install .[test]
```

5. Launch tests

```bash
python3 -m pytest tests
```



