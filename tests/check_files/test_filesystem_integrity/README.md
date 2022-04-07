# Filesystem integrity test
Wazuh - Quality Assurance system test that checks the filesystem integrity after a Wazuh installation/uninstallation/update.

The test is run using `qa-ctl` via the `launcher.py` located in the module directory. This launcher creates the `qa-ctl`
configuration, generates the playbooks that perform the actions, and calls `qa-ctl` itself. Finally, a test is launched
using pytest, to verify that the check-files obtained have no differences between them.   

# How to install

You can follow the `qa-ctl` [installation guide](https://github.com/wazuh/wazuh-qa/wiki/QACTL-tool-installation-guide)
because it is used to launch the test, and the framework is installed as well.

# How to use

After installing the `wazuh-qa` framework(you can follow the [installation guide](#how-to-install)), you will be able to run the test.

## Parameters

- `--action`, `-a`: Select the Wazuh action to be carried out to check the check-files from `install`, `upgrade`, `uninstall`.
    By default it performs an installation.

- `--os`, `-o`: Select the OS where the filesystem integrity will be tested from `centos_7`, `centos_8`, `ubuntu`.
    By default it is performed in Ubuntu Focal.

- `--version`, `-v`: Print the Wazuh installation and tests version.

- `--debug`, `-d`: Run in debug mode. You can increase the debug level with more [-d+].

- `--persistent`, `-p`: Persistent instance mode. Do not destroy the instances, check-files and qa-ctl configuration
    once the process has finished.

- `--qa-branch`: Set a custom wazuh-qa branch to download and run the tests files, `master` by default.

- `--target`, `-t`: The Wazuh test target. Could be `manager` or `agent`, with `manager` as default.

- `--no-validation`: Disable the script parameters validation.

- `--deployment-info`: Specifies the path to the file that contains the deployment information. If specified, local instances will not be deployed.

- `--output-file-path`: Specifies the path to store all test results


## Run examples

<details>
<summary>Run the test in CentOS 8 when upgrading Wazuh with custom output path.</summary>

```bash
python3 launcher.py -o centos_8 -a upgrade --output-file-path /tmp/syscheck/ubuntu/uninstall 
```

</details>

<details>
<summary>Keep the instances running. Also, the check-files and qa-ctl configuration are not erased.</summary>

```bash
python3 launcher.py -p
```

</details>

<details>
<summary>Specify the deployment information.</summary>

```bash
python3 launcher.py --deployment-info /tmp/wazuh_check_files/check_files_config_1641812606_893604.yaml
```

</details>