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

# Limitations

## Event volume limitations

### Configured operations limitation

- Each event generator instance is limited by the operations parameter, which specifies the total number of events to generate before stopping.
- For example, if operations is set to 5, the generator will produce 5 events and then stop. The event volume per generator is therefore capped
by this parameter.

### System resource limitations

- Disk space: For logEventGenerator (Simulates log file entries with rotation), the total volume of logs generated is limited by disk space.
If the logs are large or if log rotation occurs frequently, disk space may become a limiting factor.

- File system limits: For syscheckEventGenerator (Simulates file system operations (create, modify, delete)), creating a large number of files
can hit file system limits.

## Maximum generation rate

- The rate parameter specifies the number of events per second.
- The start() method in EventGenrator calculates the sleep time between events to maintain the specified rate.

### Processing overhead

- Each event involves processing tasks such as file I/O and data formatting.
- At very high rates, the processing time per event may exceed the interval calculated for the desired rate, leading to lower actual rates.

### System performance

- High rates may lead to increased CPU usage, potentially causing system slowdowns.
- Rapid file writes and modifications can saturate disk I/O bandwidth.

## Number of parallel event threads

- Each event generator instance runs in its own thread.
- The main script initiates and manages these threads.

### Limitations

- System thread limits: The operating system limits the maximum number of threads that can be created.
- Resource consumption: Each thread consumes system resources (memory and CPU time).
- Context stwitching overhead: A high number of threads can lead to increased context switching, reducing overall performance.

### Recommendations

- Keep the number of threads at a level that the system can handle efficiently.
- Monitor system performance to avoid overloading the CPU with excessive threading.

## Other potential limitations

### Disk I/O limitations

- The speed at which the disk can handle read/write operations may become a bottleneck.
- High-frequency file operations can lead to increased disk latency and I/O wait times.
- Solid-state drives (SSDs) offer faster I/O performance compared to hard disk drives (HDDs).

### CPU limitations

- The generation of events involves processing that consumes CPU resources.
- High rates and multiple threads can lead to high CPU utilization, impacting other system operations.

### Memory usage

- Each thread and its associated data structures consume memory.
- Prolonged operation with many threads may lead to increased memory usage.

## Testing performed

| Operations | Rate (EPS) | Expected Time (s) | Observed Time (s) | Difference (s) |
|------------|------------|-------------------|-------------------|----------------|
| 1,000 | 100 | 10 | 10.041 | +0.041 |
| 5,000 | 500 | 10 | 10.048 | +0.048 |
| 10,000 | 1,000 | 10 | 10.042 | +0.042 |
| 20,000 | 1,000 | 20 | 20.039 | +0.039 |
| 50,000 | 2,000 | 25 | 25.074 | +0.074 |
| 100,000 | 5,000 | 20 | 20.047 | +0.047 |
| 100,000 | 10,000 | 10 | 10.035 | +0.035 |
| 200,000 | 20,000 | 10 | 10.057 | +0.057 |
| 250,000 | 25,000 | 10 | 10.482 | +0.482 |
| 300,000 | 30,000 | 10 | 12.718 | +2.718 |
| 500,000 | 50,000 | 10 | 16.229 | +6.229 |
| 1,000,000 | 100,000 | 10 | 33.802 | +23.802 |

- Below 250,000 operations, the observed execution times closely match the expected times.
- Over 300,000 operations, the observed times start deviating from the expected times.
- The deviation increases as both the operations and the rate increase, indicating system limitations.
