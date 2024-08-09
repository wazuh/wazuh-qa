## Manager Service mocks

This package provides scripts and tools to simulate the Agent Communication and Management Server API services of the Wazuh manager. These mocks are specifically designed for performance testing of the agent and are not intended for use in a production environment.

### Scripts

- `simulate_manager`: A script to simulate the behavior of the full Wazuh manager. See the  [[manager_mock_servers/README.md]] for more details.
- `manager_server_mock`: A mock for the Management Server API services. Refer to the [[manager_services/manager_server_mock/README.md]] for more information.
- `agent_comm_mock`: A mock for the Agent Communication services. Detailed information is available in the [manager_services/agent_comm_mock/README.md].

### Installation

1. Move to the 'performance/manager_mock_servers' directory
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
