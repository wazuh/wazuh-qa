# gcp-pubsub

Google Cloud: Pub/Sub integration

## Description

It is a _wodle based_ module that has a capability to pull logs from Google Cloud Pub/Sub.

## Requirements

- It should work on both manager and agents
- The only dependency must be the Python module google-cloud-pubsub
- Python 3.6 compatible (since 2.7 will be deprecated by Google Pub/Sub in January 2020)
- The module will assume there is already a sink, topic, and a subscription created in GCP.
- No temporal files are needed. It must write directly into agentd/analysisd socket.

## Configuration settings

- project_id: String. Google Cloud Project ID. Required.
- subscription_name: String. Name of the subscription to read from. Required.
- credentials_file: String. The path to the Google Cloud credentials file. JWT Tokens. It must allow both relative (to
  $HOME_INSTALLATION) and absolute paths. Required.
- interval: String. The amount of time between each pull. Default: 1h. (It must allow the format: 1h, 1d, 20m, 1405s).
- max_messages: Integer. The number of maximum messages pulled in each iteration. Default: 100.
- enabled: String. Enable or disabled the module. Values: yes/no.
- pull_on_start: String. Trigger the pulling in case of an agent start or restart. Values: yes/no. Default: yes.
- logging: String. Toggle between the different logging levels. Values: disabled/info/debug/trace. Default: info.

Also, there are optional parameters related to schedule:

- day: Int. Day of the month when the module starts to pull messages. It can be used with _time_ parameter.
- wday: String. Day of the week when the module starts to pull messages. It cannot be used with _day_ parameter but _
  time_ parameter.
- time: String. Time when the module starts to pull messages.

## First steps

- Create a Google Cloud project.
- Create a publisher/topic in Google Cloud Pub/Sub.
- Create a subscriber in Google Cloud Pub/Sub.
- Generate a credentials json file. It can be done going to project settings >> Service Accounts. Then choose the
  Service Account >> Actions >> Create key. The default path for the credential file is /var/ossec/ but another path is
  allowed. The json file has the following structure:

```shell script
{
  "type": "service_account",
  "project_id": "wazuh-132",
  "private_key_id": "...",
  "private_key": "...",
  "client_email": "...",
  "client_id": "...",
  "auth_uri": "...",
  "token_uri": "...",
  "auth_provider_x509_cert_url": "...",
  "client_x509_cert_url": "..."
}
```

## Configuration example

To use this integration, it is necessary to add the configuration to ossec.conf:

```shell script
<gcp-pubsub>
  <project_id>wazuh-project-123</project_id>
  <subscription_name>wazuh-integration</subscription_name>
  <credentials_file>credentials.json</credentials_file>
  <max_messages>150</max_messages>
  <interval>2h</interval>
</gcp-pubsub>
```

_credentials_file_ option accepts relative and absolute path.

## Setting up a test environment

You will need a proper environment to run the integration tests. You can use any virtual machine you wish. If you have
one already, go to the [integration tests section](#integration-tests)

If you use [Vagrant](https://www.vagrantup.com/downloads.html)
or [VirtualBox](https://www.virtualbox.org/wiki/Downloads), it is important to install the `vbguest` plugin since some
tests modify the system date and there could be some synchronization issues.

This guide will cover the following platforms: [Linux](#linux) and [MacOS](#macos).

You can run these tests on a manager or an agent. In case you are using an agent, please remember to register it and use
the correct version (Wazuh branch).

_We are skipping Wazuh installation steps. For further information,
check [Wazuh documentation](https://documentation.wazuh.com/3.11/installation-guide/index.html)._

### Linux

_We are using **CentOS** for this example:_

- Install **Wazuh**

- Disable firewall (only for **CentOS**)

```shell script
systemctl stop firewalld
systemctl disable firewalld
```

- Install Python and its dependencies

```shell script
# Install dependencies
yum install make gcc policycoreutils-python automake autoconf libtool epel-release git which sudo wget -y

# Install development dependencies for jq library
yum groupinstall "Development Tools" -y

# Install Python3
yum install python36 python36-pip python36-devel -y

# Install Python libraries
pip3 install google-cloud-pubsub pytest freezegun jq jsonschema pyyaml==5.4 psutil pytest-html==2.0.1 numpydoc==0.9.2
```

- Add some internal options and restart

```shell script
# Enable debug 2
echo 'wazuh_modules.debug=2' >> $wazuh_path/etc/local_internal_options.conf
echo 'analysisd.debug=2' >> $wazuh_path/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time (only for agents)
sed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /var/ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> $wazuh_path/etc/local_internal_options.conf

# Restart Wazuh
/var/ossec/bin/wazuh-control restart
```

### MacOS

- Install **Wazuh**

- Install Python and its dependencies

```shell script
# Install Python
brew install python3

# Install dependencies
brew install autoconf automake libtool

# Install Python libraries
pip3 install google-cloud-pubsub pytest freezegun jq jsonschema pyyaml==5.4 psutil pytest-html==2.0.1 numpydoc==0.9.2
```

- Add some internal options and restart

```shell script

# Enable debug 2
echo 'wazuh_modules.debug=2' >> /Library/Ossec/etc/local_internal_options.conf
echo 'analysisd.debug=2' >> /Library/Ossec/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time
brew install gnu-sed
gsed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /Library/Ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> /Library/Ossec/etc/local_internal_options.conf

# Restart Wazuh
/Library/Ossec/bin/wazuh-control restart
```

Finally, copy your `wazuh-qa` repository within your testing environment and you are set.

## Integration tests

**DISCLAIMER:** this guide assumes you have a proper testing environment. If you do not, please check
our [testing environment guide](#setting-up-a-test-environment).

### Pytest

We use [pytest](https://docs.pytest.org/en/latest/contents.html) to run our integrity tests. Pytest will recursively
look for the closest `conftest` to import all the variables and fixtures needed for every test. If something is lacking
from the closest one, it will look for the next one (if possible) until reaching the current directory. This means we
need to run every test from the following path, where the general _conftest_ is:

```shell script
cd wazuh-qa/tests/integration
```

To run any test, we just need to call `pytest` from `python3` using the following line:

```shell script
python3 -m pytest [options] [file_or_dir] [file_or_dir] [...]
```

**Options:**

- `v`: verbosity level (-v or -vv. Highly recommended to use -vv when tests are failing)
- `s`: shortcut for --capture=no. This will show the output in real time
- `x`: instantly exit after the first error. Very helpful when using a log truncate since it will keep the last failed
  result
- `m`: only run tests matching given expression (-m MARKEXPR)
- `--tier`: only run tests with given tier (ex. --tier 2)
- `--html`: generates a HTML report for the test results. (ex. --html=report.html)
- `--default-timeout`: overwrites the default timeout (in seconds). This value is used to make a test fail if a
  condition is not met before the given time lapse. Some tests make use of this value and other has other fixed timeout
  that cannot be modified.
- `--gcp-project-id`: required. It sets the Google Cloud project id.
- `--gcp-subscription-name`: required. It sets the subscription name.
- `--gcp-credentials-file`: required. It indicates the path to the credentials file.
- `--gcp-topic-name`: optional. It sets the topic name. Some tests will fail if this option is not used although the
  topic name can be written in the tests.
- `--gcp-configuration-file`: optional. Loads default options from a configuration file. If omitted,
  `test_gcloud/data/configuration.yaml` will be used if it exists.

_Use `-h` to see the rest or check its [documentation](https://docs.pytest.org/en/latest/usage.html)._

Also, these integration tests are heavily based on [fixtures](https://docs.pytest.org/en/latest/fixture.html), so please
check its documentation for further information.

#### gcp-pubsub integration tests example

```shell script
python3 -m pytest -vvx --gcp-project-id=wazuh-project-123 --gcp-subscription-name=wazuh-integration --gcp-credentials-file=credentials.json test_gcloud/test_functioning/test_pull_on_start.py

======================================== test session starts =========================================
platform linux -- Python 3.6.9, pytest-5.3.5, py-1.5.2, pluggy-0.13.1 -- /usr/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.6.9', 'Platform': 'Linux-5.3.0-45-generic-x86_64-with-Ubuntu-18.04-bionic', 'Packages': {'pytest': '5.3.5', 'py': '1.5.2', 'pluggy': '0.13.1'}, 'Plugins': {'metadata': '1.8.0', 'html': '2.0.1'}}
rootdir: /home/daniel/Wazuh/wazuh-qa/tests/integration, inifile: pytest.ini
plugins: metadata-1.8.0, html-2.0.1
collected 2 items

test_gcloud/test_functioning/test_pull_on_start.py::test_pull_on_start[get_configuration0] PASSED               [ 50%]
test_gcloud/test_functioning/test_pull_on_start.py::test_pull_on_start[get_configuration1] PASSED               [100%]

========================================= 2 passed in 50.45s =========================================
```
