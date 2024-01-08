# Workflow Processor

The Workflow Processor is a tool for executing tasks defined in a YAML-based workflow file. It supports parallel execution of tasks with dependency management.

## Table of Contents

- [Workflow Processor](#workflow-processor)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Usage](#usage)
    - [Command Line Arguments](#command-line-arguments)
    - [Workflow File](#workflow-file)
    - [Logging](#logging)
  - [Examples](#examples)
    - [Basic Execution](#basic-execution)
    - [Parallel Execution](#parallel-execution)
    - [Dry Run](#dry-run)
  - [License](#license)

## Getting Started

### Prerequisites

Before using the Workflow Processor, make sure you have the following prerequisites installed:

- Python 3.9

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/wazuh/wazuh-qa.git
   ```

2. Navigate to the project directory:

   ```bash
   cd wazuh-qa/poc-tests/scripts/qa-workflow-engine
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

Now, you're ready to use the QA Workflow Engine.

## Usage

### Command Line Arguments

Run the workflow processor using the following command:

```bash
python main.py workflow_file.yml --threads 4 --dry-run --log-format json --log-level INFO
```

- `workflow_file.yml`: Path to the YAML-based workflow file.
- `--threads`: Number of threads to use for parallel execution (default is 1).
- `--dry-run`: Display the plan without executing tasks.
- `--log-format`: Log format (`plain` or `json`, default is `plain`).
- `--log-level`: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`, default is `INFO`).

### Workflow File

The workflow file is written in YAML format. It defines tasks, dependencies, and other configurations. See the provided examples in the `examples/` directory for reference.

### Logging

The workflow processor logs messages to the console. You can configure the log format (`plain` or `json`) and log level using command line arguments.

## Examples

### Basic Execution

```bash
python main.py examples/basic_workflow.yml
```

### Parallel Execution

```bash
python main.py examples/parallel_workflow.yml --threads 4
```

### Dry Run

```bash
python main.py examples/dry_run_workflow.yml --dry-run
```

## License

WAZUH Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
