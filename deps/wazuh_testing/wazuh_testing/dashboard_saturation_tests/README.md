# Dashboard Saturation Tests

This module contains a basic set of tests for the Wazuh Dashboard. The tests are performed using Artillery and Playwright. The tests are executed through a Python script.

The Python script needs some input parameters to perform the tests and get the results. Artillery gets the test results in JSON format and the script converts them to CSV format so they can be analyzed more easily.

```shell script
dashboard_saturation_tests/
├── data/
│   ├── lib/
│   │   ├── CookieManager.js
│   │   ├── ItemManager.js
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
├── .gitignore
├── Dockerfile
├── Makefile
├── pyproject.toml
└── README.md
```

## Prerequisites

### Install Wazuh

You need to have a Wazuh installation (including the Dashboard). You also need (for some tests) Agents connected to the Manager. The Dashboard must be accessible and have the user data and password to log in.

To run the script you need to have Python and Pip installed.

### Install Artillery + Playwright

The requirements for using Artillery + Playwright are indicative. The resources needed to run the tests depend greatly on the complexity of the tests.

| Simulated Users | CPU Cores | Memory (RAM) |
| --------------- | --------- | ------------ |
|  1 | 1 |  2 GB |
|  3 | 2 |  4 GB |
|  5 | 2 |  4 GB |
|  7 | 3 |  6 GB |
| 10 | 4 |  8 GB |
| 15 | 6 | 12 GB |
| 20 | 8 | 16 GB |

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

## Initial Setup

To run the tests, it is necessary to install the dependencies and the package. This can be done by running the following command:

1. Move to the `wazuh-qa/deps/wazuh_testing/wazuh_testing/dashboard_saturation_tests` directory

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

## Usage

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

## Using Docker

It is possible to use the `Docker` image with the entire environment set up for running tests. To facilitate its use, there is a `makefile` file with the necessary instructions. An example of use would be:

```shell script
make init
make test COMMAND_OPTIONS='--password <wazuh_pass> --ip <dashboard_ip>'
```

By default, test results are saved in an `artifacts` folder on the host machine. If you need help with the `makefile` it is possible to run `make help` to get an overview of all the available commands and what they do.

The `make exec` command (and, by extension, the `make test` command) requires the `COMMAND_OPTIONS` parameter since Artillery needs at least two pieces of data to function correctly: the IP of the Wazuh Dashboard and the password of the `admin` user.

In the Docker container, everything is in the `/app` directory. In `/app`, Artillery, Playwright and everything else necessary for them to work are installed. In `/app/dashboard_saturation_tests` are all the scripts. In that directory, the packages are installed and all the commands are executed.

## Analysis of the Results

### CSV

Running tests generates two types of CSV files:

- `Intermediate`: These represent intermediate statistics that are generated and printed to the console during the test run. By default, they’re generated every 10 seconds. These data points are useful for monitoring the progress of the test in real time.
    - `Summaries`: These include partial summaries during the test execution. Useful for seeing application behavior in specific intervals.
    - `Histograms`: Show the distribution of response times and other metrics in specific time intervals. Helps to identify performance peaks and dips.
    - `Counters`: Show the number of requests, errors, and other events during specific intervals of the test. Ideal for monitoring progress and quickly spotting issues.

- `Aggregate`: These represent the overall statistics for the entire duration of the test. They correspond to the final statistics printed after the test completes. These data provide a complete summary of the test's performance.
    - `Summaries`: Provides an overall view of performance across the entire test once it’s completed.
    - `Histograms`: Offers a general view of how performance metrics were distributed over time during the entire test. Useful for checking consistency and stability.
    - `Counters`: Provides a total summary of completed requests, errors, and key events at the end of the test. Gives a clear picture of overall performance.

### Logs

The log file generated by Artillery contains detailed information about each HTTP request made during the test.

This information is useful for analyzing the performance and efficiency of HTTP requests during load testing.

### Screenshots

Taking screenshots of the dashboard during load tests is a good idea for several reasons:

- `Visual Documentation`: It allows you to document the performance and stability of the system visually during the tests. This is particularly useful for reports and presentations.

- `Detailed Analysis`: You can compare screenshots from different moments to identify patterns or recurring issues that might not be evident from numerical data alone.

- `Problem-Solving`: If something goes wrong, having a screenshot of the exact moment can help identify what was happening in the system at that specific point.

- `Effective Communication`: It's much easier to explain problems and solutions to the team when you can show them exactly what was happening through screenshots.

Screenshots provide an additional layer of information and context that can be crucial to understanding and improving system performance.

## Example

This is an example of the most basic test execution and its corresponding result.

```shell script
dashboard-saturation-tests -p password -i ip
```

By default, the output is stored in 3 folders: `csv/`, `logs/` and `screenshots/`. This can be changed via the command parameters.

- Result: [report.zip](https://github.com/user-attachments/files/16542340/report.zip)
