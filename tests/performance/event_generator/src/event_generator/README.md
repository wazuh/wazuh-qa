# Event Generator Library

# Overview
The Event Generator Library is designed to simulate log and file operation events for testing and validation purposes. It offers a versatile setup for generating a variety of simulated events that can help in monitoring and analyzing the behavior of different systems under various conditions.

# Features
- **Log Event Simulation: ** Simulate log generation with customizable templates and automatic log rotation based on size constraints.
- **File System Event Simulation: ** Simulate file operations like creation, modification, and deletion to test system responses.
- **Configurable Event Rate: ** Control the rate of event generation to simulate different load scenarios.

# Classes
- `EventGenerator`: Abstract base class for generating events. Subclasses must implement the `generate_event()` method.
- `LogEventGenerator`: Generates log events to a specified file and handles log rotation.
- `SyscheckEventGenerator`: Simulates file system events and keeps track of the changes.

# Usage

The library is used by creating instances of the provided generator classes and invoking their methods to start event generation.

# Configuration

Modify the config.yaml to set up the parameters for event generation, such as the path, rate, and type of events.
