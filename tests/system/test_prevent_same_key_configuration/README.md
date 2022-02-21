# Prevent same key configuration test
System test that checks 2 scenarios:
1. When the auto-enrollment option is disabled, the manager rejects a new agent connection when it receives the same key configuration from such an agent (until the first connection is closed).
2. When the auto-enrollment option is enabled, the manager assigns a new key configuration to the new agent.

The test is run using `qa-ctl` via the `launcher.py` located in the test directory. This launcher creates the `qa-ctl`
configuration, generates the playbooks that perform the actions, and calls `qa-ctl` itself. Finally, a test is launched
using pytest, to verify the scenarios.   

# How to install

You can follow the `qa-ctl` [installation guide](https://github.com/wazuh/wazuh-qa/wiki/QACTL-tool-installation-guide)
because it is used to launch the test, and the framework is installed as well.

# How to use

After installing the `wazuh-qa` framework(you can follow the [installation guide](#how-to-install)), you will be able to run the test.

## Parameters

- `--auto-enrollment`, `-a`: Enable the agent enrollment.

- `--os`, `-o`: Select the OS where the test will be performed from `centos_7`, `centos_8`, `ubuntu`. `centos_8` is selected by default.

- `--version`, `-v`: Wazuh version.

- `--debug`, `-d`: Run in debug mode. You can increase the debug level with more [-d+].

- `--persistent`, `-p`: Persistent instance mode. Do not destroy the instances and test files once the process has finished.

- `--qa-branch`: Set a custom wazuh-qa branch to download and run the tests files, `master` by default.

- `--output-file-path`: Specifies the path to store all test results


## Run examples

<details>
<summary>Run the test in CentOS 8 with the enrollment option enabled, saving the test results in the specified path.</summary>

```bash
python3 launcher.py -a -o centos_8 --output-file-path ./custom_results_path
```

</details>

<details>
<summary>Do not destroy the instances and test files once the process has finished.</summary>

```bash
python3 launcher.py -p
```

</details>
