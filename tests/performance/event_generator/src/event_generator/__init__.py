# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Event generator module.

This module provides classes for generating simulated log and file events for testing purposes. It supports generating
events at specified rates and managing file sizes and formats, thereby providing a flexible setup for system load
and behavior simulations.

### Usage:

Use this module to instantiate log or system event generators based on specified configurations:

```python
from event_generator import LogEventGenerator, SyscheckEventGenerator
log_generator = LogEventGenerator(rate=1, path='/var/log/test.log', operations=100, max_file_size=10, template_path='template.json')
syscheck_generator = SyscheckEventGenerator(rate=1, path='/tmp', operations=50)
```

### Arguments:

    - rate (int): Frequency of events per second.
    - path (str): Path where logs or files will be stored.
    - operations (int): Total number of events to generate.
    - max_file_size (int, optional): Maximum file size in MB before rotation (only for log generator).
    - template_path (str, optional): Path to a JSON template file for log formatting (only for log generator).

This module aims to facilitate testing by simulating workload and monitoring system behaviors.
"""

from .event_generator import EventGenerator, LogEventGenerator, SyscheckEventGenerator
