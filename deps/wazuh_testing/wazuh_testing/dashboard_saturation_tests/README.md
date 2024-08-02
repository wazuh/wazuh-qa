# Dashboard Saturation Tests

This module contains a basic set of tests for the Wazuh Dashboard. The tests are performed using Artillery and Playwright. The tests are executed through a Python script.

The Python script needs some input parameters to perform the tests and get the results. Artillery gets the test results in JSON format and the script converts them to CSV format so they can be analyzed more easily.

```shell script
dashboard_saturation_tests/
├── lib/
│   ├── CookieManager.py
│   ├── PathManager.py
│   └── ScreenshotManager.py
├── test/
│   ├── EndpointTest.js
│   ├── LoginTest.js
│   └── OverviewTest.js
├── artillery.yml
├── dashboard_saturation_tests.py
└── processor.js
```

## Prerequisites

### Install Wazuh

You need to have a Wazuh installation (including the Dashboard). You also need (for some tests) Agents connected to the Manager. The Dashboard must be accessible and have the user data and password to log in.

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

To run these tests, we need the wazuh-testing package. So first, we need to install all these Python dependencies, we can use this command:

```shell script
pip3 install -r requirements.txt
```

Then, we need to install the package:

```shell script
cd deps/wazuh_testing
python3 setup.py install
```

## Artillery + Playwright

To run the tests, we will need to use the following command:

```shell script
python3 -m dashboard_saturation_tests.py --password <wazuh_pass> --ip <dashboard_ip>
```

### Parameters

| Parameter | Description | Type | Required | Default |
| --------- | ----------- | ---- | -------- | ------- |
| `-l`, `--logs` | `Directory to store the logs` | `str` | No | `logs/` |
| `-s`, `--screenshots` | `Directory to store the screenshots` | `str` | No | `screenshot/` |
| `-c`, `--csv` | `Directory to store the CSVs` | `str` | No | `csv/` |
| `-o`, `--session` | `Directory to store the Sessions` | `str` | No | `.auth/` |
| `-a`, `--artillery` | `Path to the Artillery Script` | `str` | No | `artillery.yml` |
| `-u`, `--user` | `Wazuh User for the Dashboard` | `str` | No | `admin` |
| `-p`, `--password` | `Wazuh Password for the Dashboard` | `str` | Yes | None |
| `-q`, `--quantity` | `Number of Tests to Run` | `int` | No | `1` |
| `-i`, `--ip` | `Set the Dashboard IP` | `str` | Yes | None |
| `-t`, `--type` | `JSON data to create the CSV` | `list` | No | `['aggregate', 'intermediate']` |
| `-w`, `--wait` | `Waiting Time between Executions` | `int` | No | `1` |
| `-d`, `--debug` | `Enable debug mode` | `store_true` | No | `False` |

### Parameters restrictions

- `--logs`, `--screenshots`, `--csv`, and `--session` are directories (if they do not exist, they are created in the Script).
- `--artillery` needs to receive a valid Artillery configuration file.
- `--type` only accepts the options received in the Artillery JSON file with the results.

### Example

```shell script
python3 -m dashboard_saturation_tests -p password -i 172.16.1.36
```

- Result: [report.zip](https://github.com/user-attachments/files/16456792/report.zip)