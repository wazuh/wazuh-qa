# Setting up a test environment

You will need a proper environment to run the integration tests. You can use any virtual machine you wish. If you have one already, go to the [integration tests section](#integration-tests)

If you use [Vagrant](https://www.vagrantup.com/downloads.html) or [VirtualBox](https://www.virtualbox.org/wiki/Downloads), it is important to install the `vbguest` plugin since some tests modify the system date and there could be some synchronization issues.

This guide will cover the following platforms: [Linux](#linux), [Windows](#windows) and [MacOS](#macos).

You can run these tests on a manager or an agent. In case you are using an agent, please remember to register it and use the correct version (Wazuh branch).

_We are skipping Wazuh installation steps. For further information, check [Wazuh documentation](https://documentation.wazuh.com/3.11/installation-guide/index.html)._

## Linux

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
pip3 install pytest freezegun jq jsonschema pyyaml==5.3 psutil paramiko distro pandas pytest-html==2.0.1 numpydoc==0.9.2
```

- Add some internal options and restart

```shell script
# Enable debug 2
echo 'syscheck.debug=2' >> $wazuh_path/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time (only for agents)
sed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /var/ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> $wazuh_path/etc/local_internal_options.conf

# Restart Wazuh
/var/ossec/bin/ossec-control restart
```

-----------

## Windows

- Install **Wazuh**

- Download and install [Python](https://www.python.org/downloads/windows/)

- Download and install [chocolatey](https://chocolatey.org/docs/installation) to be able to install `jq` using the terminal.

- Install `jq`:

```shell script
choco install jq
```

- Install Python dependencies

```shell script
pip install pytest freezegun jsonschema pyyaml==5.3 psutil paramiko distro pywin32 pypiwin32 wmi pandas pytest-html==2.0.1 numpydoc==0.9.2
```

- Change `time-reconnect` from `C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<time-reconnect>99999999999</time-reconnect>
```

- Add some internal options

```shell script
# Enable debug 2
echo 'syscheck.debug=2' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

# Disable log rotation
echo 'monitord.rotate_log=0' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
```

- Restart **Wazuh** using the GUI

-----------

## MacOS

- Install **Wazuh**

- Install Python and its dependencies

```shell script
# Install Python
brew install python3

# Install dependencies
brew install autoconf automake libtool

# Install Python libraries
pip3 install pytest freezegun jq jsonschema pyyaml==5.3 psutil paramiko distro pandas pytest-html==2.0.1 numpydoc==0.9.2
```

- Add some internal options and restart

```shell script

# Enable debug 2
echo 'syscheck.debug=2' >> /Library/Ossec/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time
brew install gnu-sed
gsed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /Library/Ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> /Library/Ossec/etc/local_internal_options.conf

# Restart Wazuh
/Library/Ossec/bin/ossec-control restart
```

-----------

Finally, copy your `wazuh-qa` repository within your testing environment and you are set.