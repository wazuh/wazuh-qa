# Scans

This directory contains scripts used to scan and verify Wazuh Python code and its dependencies.

### Getting started

In order to run the scripts, you should install the `wazuh_testing` package and the dependencies listed in the requirements file. 

These are the steps to do so:

> Your terminal should be at the root of the `wazuh-qa` repository.

1. Create and activate a virtual environment

```console
python3 -m venv venv
source venv/bin/activate
```

2. Install the dependencies

```console
pip install -r requirements.txt
```

3. Build the `wazuh_testing` package

```console
pip install deps/wazuh_testing/
```

That's all it takes, you can now run the [code analysis](./code_analysis/README.md) and [dependencies](./dependencies/README.md) vulnerability scanning tools.
