"""Manager Service Mocks.

This package provides tools and scripts for simulating the Wazuh manager's Agent Communication and
Management Server API services. These mocks are primarily designed for performance testing of the
agent and are not intended for use in production environments.

Modules:
    - `simulate_manager`: Simulates the behavior of the full Wazuh manager,
    including both agent communication and management API services.
    - `simulate-management-server`: Mocks the Management Server API services.
    - `simulate-agent-comm`: Mocks the Agent Communication services.

Usage:
    The `simulate_manager` script can be used to simulate a full manager setup by specifying the management and
    agent communication ports, server path, and report path. Alternatively, the agent communication and management
    API services can be run separately, but SSL credentials are required for HTTPS support.

Installation:
    1. Navigate to the `performance/manager_mock_servers` directory.
    2. Create and activate a Python virtual environment.
    3. Install the package using pip.

Testing:
    The package includes tests that can be run by setting up a separate Python testing environment and using pytest.

Note:
    Refer to the respective README files for detailed instructions and further information.
"""
