# Mock Server Manager

This script manages and runs mock server services for testing purposes. It includes functionalities for starting server and agent communication services, generating necessary SSL certificates, and handling process management.

## Usage

Run the script as a standalone program. The `main()` function handles the initialization and management of the mock services based on the provided command-line arguments. The script ensures proper handling of the services and cleans up resources appropriately upon termination.

**Example Usage:**

```sh
python script.py --manager-api-port 60000 --agent-comm-api-port 3000 --server-path /path/to/server --report-path /path/to/report.csv
```

### Arguments

    --manager-api-port: Port for the mock server management service. Default is 55000.
    --agent-comm-api-port: Port for the mock agent communication service. Default is 2900.
    --server-path: Path to the directory where server files are located. If not specified, a temporary directory will be used.
    --report-path: Path to the CSV file where metrics will be reported (required).
    --debug: Enable debug mode.
