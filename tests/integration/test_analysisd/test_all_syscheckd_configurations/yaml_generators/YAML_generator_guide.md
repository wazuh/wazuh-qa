# YAML generator guide

It is important to have Wazuh running beforehand and the package `wazuh_testing` installed.

## Linux

On Linux you just have to run the script `generate_linux_yaml.py` to generate it.

```
# python3 generate_linux_yaml.py -h

usage: usage: generate_linux_yaml.py [options]

Analysisd YAML generator (Linux)

optional arguments:
  -h, --help            show this help message and exit
  -e N_EVENTS, --events N_EVENTS
                        Specify how many events will be expected to be created and deleted. Default 4096.
  -m MODIFIED_EVENTS, --modified MODIFIED_EVENTS
                        Specify how many modified events will be expected. Default 4088.
  -d {DEBUG,ERROR}, --debug {DEBUG,ERROR}
                        Specify debug level. Default "ERROR".
```

In linux, we currently have 4096 possible configurations. This means we are expecting 4096 "added" and "deleted" events.
From these, 8 are not generating "modified" events due to their _check\_*_ configuration.

**Example:**

```
python3 generate_linux_yaml.py -e 4098 -m 4088 -d DEBUG
```

## Windows

On Windows you need to run two scripts: one that will generate all the events on Windows (agent) and the other one, that
will recollect all the alerts on Linux (manager).

Having Wazuh running on Windows and Linux, first run `generate_windows_events.py`.

```
# python3 generate_windows_events.py -h

usage: usage: generate_windows_events.py [options]

Syscheck event generator (Windows)

optional arguments:
  -h, --help            show this help message and exit
  -t TIME_SLEEP, --time TIME_SLEEP
                        Time to sleep until the events will be generated. Default 5.
  -d {DEBUG,ERROR}, --debug {DEBUG,ERROR}
                        Specify debug level. Default "ERROR".
```

**Example:**

```
python generate_windows_events.py -t 10 -d DEBUG
```

You need to wait until you see the following message:

```
Waiting <TIME_SLEEP> seconds. Execute `generate_windows_yaml.py` now.
```

Once you see it, run `generate_windows_yaml.py` on Linux.

```
# python3 generate_windows_yaml.py -h

usage: python3 generate_windows_yaml.py [options]

Analysisd YAML generator (Windows)

optional arguments:
  -h, --help            show this help message and exit
  -e N_EVENTS, --events N_EVENTS
                        Specify how many events will be expected. Default 4096.
  -m MODIFIED_EVENTS, --modified MODIFIED_EVENTS
                        Specify how many modified events will be expected. Default 4080.
  -d {DEBUG,ERROR}, --debug {DEBUG,ERROR}
                        Specify debug level. Default "ERROR".

```

From Windows we currently expect the same number of "added" and "deleted" events but the "modified" ones are different:

**Example:**

```
python3 generate_windows_yaml.py -e 4096 -m 4080 -d DEBUG
```

----

These scripts will generate their respective YAMLs on the same path under the names of `syscheck_events.yaml` (Linux)
and `syscheck_events_win32.yaml` (Windows).