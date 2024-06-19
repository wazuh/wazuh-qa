# Wazuh's InfluxDB plugin for pytest

This is a plugin to send the results of the tests to an InfluxDB database.

## Installation

> This plugin is not available in PyPI yet. You can install it from source.

1. Clone the repository
    ```shellsession
    $ git clone https://github.com/wazuh/wazuh-qa.git -b <YOUR_BRANCH>
    ```
2. Open the repository folder
    ```shellsession
    $ cd wazuh-qa/poc-test/src/plugins
    ```
3. Install the plugin
    ```shellsession
    $ pip install influxdb_reporter
    ```

## Usage

There are three ways to configure the plugin: by a configuration file, by command line arguments or by environment variables. In that order, the plugin will look for the configuration, if it is not found, it will look for the arguments, and if they are not found, it will look for the environment variables.

### Using environment variables

1. Configure the environment env on your system
    ```bash
    $ export INFLUXDB_URL="http://localhost:8086"
    $ export INFLUXDB_TOKEN="my-token"
    $ export INFLUXDB_BUCKET="my-bucket"
    $ export INFLUXDB_ORG="my-org"
    ```
2. Execute the test using the `--influxdb-report` flag
    ```bash
    $ pytest test_name.py --influxdb-report
    ```

### Using command line arguments

1. Execute the test using the `--influxdb-report` flag and the required arguments
    ```bash
    $ pytest test_name.py --influxdb-report --influxdb-url "http://localhost:8086" --influxdb-token "my-token" --influxdb-bucket "my-bucket" --influxdb-org "my-org"
    ```

### Using influxdb configuration file

1. Execute the test using the `--influxdb-report` flag and the path to the configuration file
    ```bash
    $ pytest test_name.py --influxdb-report --influxdb-config-file "path/to/config/file"
    ```

    > The configuration file must be a json file with the following structure:
    > ```json
    > {
    >     "url": "http://localhost:8086",
    >     "token": "my-token",
    >     "bucket": "my-bucket",
    >     "org": "my-org"
    > }
    > ```
