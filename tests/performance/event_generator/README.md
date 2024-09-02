# Event generator system

This repository contains tools and scripts designed to simulate log and file system events. These tools are ideal for performance and stability testing of monitoring systems.

# Components

- **Log Event Generator**: Simulates logging events at specified intervals and volumes. Can be configured for log rotation based on size constraints.
- **File System Event Generator**: Simulates file creation, modification, and deletion events, useful for testing file integrity monitoring systems.

# Usage

To run the event generation system, you can use the `main.py` script with an associated configuration file(`config.yaml`). This setup allows you to define detailed parameters for the simulation of log and file events.

```bash
python3 main.py --config config.yaml
```

This command starts the event simulation as specified in config.yaml, handling both log generation and file system events based on the module configurations defined within the file.

# Configuration

Modify the config.yaml file to set the types of events, frequency, target paths for logs and file operations, among other parameters. An example configuration might look like this:

```yaml
files:
  - module: logcollector
    path: /path/to/logfile.log
    operations: 100
    rate: 2
    max_file_size: 10
    template_path: templates/syslog_template.json
    cleanup: true

  - module: syscheck
    path: /path/to/test/directory
    operations: 50
    rate: 1
    cleanup: true
```

# Installation

1. Move to the `event_generator` directory
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

5. Running the application
```bash
event-generator --config config.yaml
```

# Tests

To run the package tests, follow these steps:

1. Move to the 'event_generator' directory
2. Create the Python environment

```bash
python3 -m venv testing-env
```

3. Activate the environment:
```bash
source testing-env/bin/activate
```

4. Install the package
```bash
python3 -m pip install .[dev]
```

5. Launch tests

```bash
python3 -m pytest tests
```
