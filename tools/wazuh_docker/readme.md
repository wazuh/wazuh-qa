# Wazuh docker utilities

Create Wazuh manager or agent containers in one simple command!

Specify the version to install or even your own custom package, select the target (manager or agent) and create your
container in less than 1 minute :rocket:.

## Usage

Download this repository and build the docker image:

```
docker build -t jmv74211/wazuh .
```

When the container is created, a script will automatically run that will install and configure wazuh. The parameters
to be taken into account are the following:

```
usage: entrypoint.py [-h] -t <target> [-v <version>] [-p <package_url>] [-m <manager_registration_ip>]
                     -o <os> [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -t <target>, --target <target>
                        Wazuh component target
  -v <version>, --version <version>
                        Wazuh install version
  -p <package_url>, --package-url <package_url>
                        Custom package URL to install
  -m <manager_registration_ip>, ---manager-registration-ip <manager_registration_ip>
                        Manager registration IP. Specify it only if your target is agent
  -o <os>, --os <os>    Container OS distribution
  --debug               Activate debug logging
```

## Examples

Create a container with a `wazuh-manager` version `4.3.9` (relesed version)

```
docker run --rm jmv74211/wazuh -t manager -v 4.3.9
```

You can also create with containers that have development versions, specifying the URL of the package to install:

```
docker run --rm jmv74211/wazuh -t manager -p https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/test/4.4/deb/wazuh-manager_4.4.0-logcollector.only.future.events_amd64.deb
```

If you want to create agents, you can do it in the same way, adding an additional parameter that will be the IP
address of the manager to which the agent is going to connect.


```
docker run --rm jmv74211/wazuh -t agent -v 4.3.9 -m 172.17.0.3
```

In the same way, you can also specify custom packages instead of using a relese version:

```
docker run --rm jmv74211/wazuh -t agent -m 172.17.0.2 -p https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/test/4.4/deb/wazuh-agent_4.4.0-logcollector.only.future.events_amd64.deb
```

> Note: In case you want to run them in the background, remember that you can do it with docker run -d ...
