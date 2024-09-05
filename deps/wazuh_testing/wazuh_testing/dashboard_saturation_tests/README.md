# Dashboard Saturation Tests

This module contains a basic set of tests for the Wazuh Dashboard. The tests are performed using Artillery and Playwright. The tests are executed through a Python script.

The Python script needs some input parameters to perform the tests and get the results. Artillery gets the test results in JSON format and the script converts them to CSV format so they can be analyzed more easily.

```shell script
dashboard_saturation_tests/
├── data/
│   ├── lib/
│   │   ├── CookieManager.js
│   │   ├── PathManager.js
│   │   └── ScreenshotManager.js
│   ├── tests/
│   │   ├── EndpointTest.js
│   │   ├── EventTest.js
│   │   ├── LoginTest.js
│   │   └── OverviewTest.js
│   ├── __init__.py
│   ├── artillery.xml
│   ├── dashboard_saturation_tests.py
│   └── processor.js
├── README.md
└── pyproject.toml
```

## Prerequisites

### Install Wazuh

You need to have a Wazuh installation (including the Dashboard). You also need (for some tests) Agents connected to the Manager. The Dashboard must be accessible and have the user data and password to log in.

To run the script you need to have Python and Pip installed.

### Install Artillery + Playwright

Artillery, Playwright and all the dependencies required for them to run correctly must be installed. Some dependencies are libraries that can be used in tests.

```shell script
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install Artillery
npm install -g artillery

# Install Playwright
npm install -g playwright

# Install Dependencies
npm install @playwright/test
npx playwright install-deps

# Check Installed Versions
artillery --version
playwright --version
```

## Initial setup

To run the tests, it is necessary to install the dependencies and the package. This can be done by running the following command:

```shell script
python3 -m venv env
source env/bin/activate
python3 -m pip install .
```

Note: The use of the environment is optional,

## Artillery + Playwright

To run the tests, we will need to use the following command:

```shell script
dashboard-saturation-tests --password <wazuh_pass> --ip <dashboard_ip>
```

### Parameters

| Parameter | Description | Type | Required | Default |
| --------- | ----------- | ---- | -------- | ------- |
| `-l`, `--logs` | `Directory to store the logs` | `str` | No | `logs/` |
| `-s`, `--screenshots` | `Directory to store the screenshots` | `str` | No | `screenshots/` |
| `-c`, `--csv` | `Directory to store the CSVs` | `str` | No | `csv/` |
| `-o`, `--session` | `Directory to store the Sessions` | `str` | No | `.auth/` |
| `-a`, `--artillery` | `Path to the Artillery Script` | `str` | No | `data/artillery.yml` |
| `-u`, `--user` | `Wazuh User for the Dashboard` | `str` | No | `admin` |
| `-p`, `--password` | `Wazuh Password for the Dashboard` | `str` | Yes | None |
| `-q`, `--iterations` | `Number of Tests to Run` | `int` | No | `1` |
| `-i`, `--ip` | `Set the Dashboard IP` | `str` | Yes | None |
| `-t`, `--type` | `JSON data to create the CSV` | `list` | No | `['aggregate', 'intermediate']` |
| `-w`, `--wait` | `Waiting Time between Executions` | `int` | No | `1` |
| `-d`, `--debug` | `Enable debug mode` | `store_true` | No | `False` |

### Parameters restrictions

- `--logs`, `--screenshots`, `--csv`, and `--session` are directories (if they do not exist, they are created in the Script).
- `--artillery` needs to receive a valid Artillery configuration file (for example, `artillery.yml`).
- `--type` only accepts two values ​​(`aggregate` or `intermediate`). Either or both can be chosen.

### Check PEP 8

The Python script complies with the PEP 8 standard. To verify that it continues to comply with the standard (after making changes) you just have to execute the following commands:

```shell script
pycodestyle dashboard_saturation_tests.py
```

## Using Docker

It is possible to use the `Docker` image with the entire environment set up for running tests. To facilitate its use, there is a `makefile` file with the necessary instructions. An example of use would be:

```shell script
make init
make test COMMAND_OPTIONS='--password <wazuh_pass> --ip <dashboard_ip>'
```

By default, test results are saved in an `artifacts` folder on the host machine. If you need help with the `makefile` it is possible to run `make help` to get an overview of all the available commands and what they do.

The `make exec` command (and, by extension, the `make test` command) requires the `COMMAND_OPTIONS` parameter since Artillery needs at least two pieces of data to function correctly: the IP of the Wazuh Dashboard and the password of the `admin` user.

In the Docker container, everything is in the `/app` directory. In `/app`, Artillery, Playwright and everything else necessary for them to work are installed. In `/app/dashboard_saturation_tests` are all the scripts. In that directory, the packages are installed and all the commands are executed.

## Example

```shell script
dashboard-saturation-tests -p password -i ip
```

- Result: [report.zip](https://github.com/user-attachments/files/16542340/report.zip)