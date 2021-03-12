# Setting up a test environment

You will need a proper environment to run the integration tests. You can use any virtual machine you wish. If you have 
one already, go to the [integration tests section](../)

If you use [Vagrant](https://www.vagrantup.com/downloads.html) or 
[VirtualBox](https://www.virtualbox.org/wiki/Downloads), it is important to install the `vbguest` plugin since some 
tests modify the system date and there could be some synchronization issues.

This guide will cover the following platforms: [Linux](#linux), [Windows](#windows) and [MacOS](#macos).

You can run these tests on a manager or an agent. In case you are using an agent, please remember to register it and 
use the correct version (Wazuh branch).

> Note: We are skipping Wazuh installation steps. For further information, check 
> [Wazuh documentation](https://documentation.wazuh.com/3.13/installation-guide/index.html).

## Linux

_We are using **CentOS** for this example:_

- Install **Wazuh**

- Disable all components in `ossec.conf`

- Disable firewall (only for **CentOS**)

```
systemctl stop firewalld
systemctl disable firewalld
```

- Install Python and the development tools

```
# Install dependencies
yum install make gcc policycoreutils-python-utils automake autoconf libtool epel-release git which sudo wget -y

# Install the development dependencies for jq library
yum groupinstall "Development Tools" -y

# Install Python3
yum install python36 python3-pip python36-devel -y
```

- Add some internal options and restart

```
# Enable debug 2
echo 'syscheck.debug=2' >> $wazuh_path/etc/local_internal_options.conf
echo 'wazuh_modules.debug=2' >> $wazuh_path/etc/local_internal_options.conf
echo 'wazuh_db.debug=2' >> $wazuh_path/etc/local_internal_options.conf


# Avoid agent disconnections when travelling in time (only for agents)
sed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /var/ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> $wazuh_path/etc/local_internal_options.conf

# Restart Wazuh
/var/ossec/bin/ossec-control restart
```

- Download wazuh-qa repository, install the requirements and the package dependencies..

```
# Download wazuh-qa repository
git clone https://github.com/wazuh/wazuh-qa.git

# Install the requirements
python3 -m pip install -r wazuh-qa/requirements.txt

# Install wazuh_testing package
python3 wazuh-qa/deps/wazuh_testing/setup.py install
```

-----------

## Windows

- Install **Wazuh**

- Disable all components in `ossec.conf`

- Download and install [Python](https://www.python.org/downloads/windows/)

- Download and install [chocolatey](https://chocolatey.org/docs/installation) to be able to 
  install `jq` using the terminal.

- Install `jq`:

```
choco install jq
```


- Change `time-reconnect` from `C:\Program Files (x86)\ossec-agent\ossec.conf`

__xml__
```
<time-reconnect>99999999999</time-reconnect>
```

- Add some internal options

```
# Enable debug 2
echo 'syscheck.debug=2' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo 'wazuh_modules.debug=2' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
echo 'wazuh_db.debug=2' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

# Disable log rotation
echo 'monitord.rotate_log=0' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
```

- Restart **Wazuh** using the GUI

- Download wazuh-qa repository, install the requirements and the package dependencies.

```
# Download wazuh-qa repository
git clone https://github.com/wazuh/wazuh-qa.git

# Install requirements
python3 -m pip install -r wazuh-qa/requirements.txt

# Install wazuh_testing package
python3 wazuh-qa/deps/wazuh_testing/setup.py install
```

-----------

## MacOS

- Install **Wazuh**

- Disable all components in `ossec.conf`

- Install Python and the development tools

```
# Install Python
brew install python3

# Install dependencies
brew install autoconf automake libtool

```

- Add some internal options and restart

```

# Enable debug 2
echo 'syscheck.debug=2' >> /Library/Ossec/etc/local_internal_options.conf
echo 'wazuh_modules.debug=2' >> /Library/Ossec/etc/local_internal_options.conf
echo 'wazuh_db.debug=2' >> /Library/Ossec/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time
brew install gnu-sed
gsed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g"
/Library/Ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> /Library/Ossec/etc/local_internal_options.conf

# Restart Wazuh
/Library/Ossec/bin/ossec-control restart
```

- Download wazuh-qa repository, install the requirements and the package dependencies..

```
# Download wazuh-qa repository
git clone https://github.com/wazuh/wazuh-qa.git

# Install requirements
python3 -m pip install -r wazuh-qa/requirements.txt

# Install wazuh_testing package
python3 wazuh-qa/deps/wazuh_testing/setup.py install
```
