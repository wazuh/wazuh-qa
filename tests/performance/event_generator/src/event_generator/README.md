# Event Generator Library

# Overview
The Event Generator Library is designed to simulate log and file operation events for testing and validation purposes. It offers a versatile setup for generating a variety of simulated events that can help in monitoring and analyzing the behavior of different systems under various conditions.

# Features
- **Log Event Simulation:** Simulate log generation with customizable templates and automatic log rotation based on size constraints.
- **File System Event Simulation:** Simulate file operations like creation, modification, and deletion to test system responses.
- **Configurable Event Rate:** Control the rate of event generation to simulate different load scenarios.

# Classes
- `EventGenerator`: Abstract base class for generating events. Subclasses must implement the `generate_event()` method.
- `LogEventGenerator`: Generates log events to a specified file and handles log rotation.
- `SyscheckEventGenerator`: Simulates file system events and keeps track of the changes.

# Usage

The library is used by creating instances of the provided generator classes and invoking their methods to start event generation.

# Configuration

Modify the config.yaml to set up the parameters for event generation, such as the path, rate, and type of events.

# Limitations

A test of the limitations of the event creation tool has been carried out.

It has been tested with Ubuntu 22, Ubuntu 20, Amaozn Linux 2, Amazon Linux 2023 and CentOS 8 operating systems.
With different RAM memory settings from 2GB to 16GB and from 1CPU to 12 CPUs.
It has been performed on a pc with the following characteristics:

 - Model: Intel Core i7-10750H @ 2.60 GHz (6 cores, 12 threads).
 - CPU Features: The CPU has 6 physical cores and supports Hyper-Threading (12 threads).
 - Max Clock Speed: 5.0 GHz.
 - Virtualization: Supports Intel VT-x for virtual machines.
 - Total RAM: 16 GB (15 GiB usable).
 - Storage: NVMe SSD.

From all the testing performed we can obtain these averages and results:

| Operations | Rate (EPS) | Expected Time (s) | Observed Time (s) | Difference (s) |
|------------|------------|-------------------|-------------------|----------------|
| 100 | 10 | 10 | 10,046 | +0.046 |
| 1,000 | 100 | 10 | 10.041 | +0.041 |
| 5,000 | 500 | 10 | 10.048 | +0.048 |
| 10,000 | 1,000 | 10 | 10.042 | +0.042 |
| 20,000 | 1,000 | 20 | 20.039 | +0.039 |
| 50,000 | 2,000 | 25 | 25.074 | +0.074 |
| 100,000 | 5,000 | 20 | 20.047 | +0.047 |
| 100,000 | 10,000 | 10 | 10.035 | +0.035 |
| 200,000 | 20,000 | 10 | 10.057 | +0.057 |
| 250,000 | 25,000 | 10 | 10.482 | +0.482 |
| 300,000 | 30,000 | 10 | 10,055 | +0.055 |
| 325,000 | 32,500 | 10 | 10,911 | +0.911 |
| 350,000 | 35,000 | 10 | 11,307 | +1.307 |
| 400,000 | 40,000 | 10 | 11,130 | +1.130 |
| 500,000 | 50,000 | 10 | 13,991 | +3,991 |
| 1,000,000 | 100,000 | 10 | 28,516 | +18,516 |

- The system performs well for small to medium workloads (up to 300,000 events or 30,000 EPS), with small variations in observed times.
- As event rates exceed 300,000 events or 30,000 EPS, performance begins to degrade significantly.
- As we see that the limit is 30,000 EPS, we perform a test with this value:

| Operations | Rate (EPS) | Expected Time (s) | Observed Time (s) | Difference (s) |
|------------|------------|-------------------|-------------------|----------------|
| 1,000      | 30,000     | 0.033             | 0.074             | +0.041         |
| 10,000     | 30,000     | 0.333             | 0.375             | +0.042         |
| 100,000    | 30,000     | 3.333             | 3.378             | +0.045         |
| 200,000    | 30,000     | 6.667             | 6.718             | +0.051         |
| 250,000    | 30,000     | 8.333             | 8.492             | +0.159         |
| 300,000    | 30,000     | 10.000            | 10.879            | +0.879         |
| 400,000    | 30,000     | 13.333            | 14.459            | +1.126         |
| 500,000    | 30,000     | 16.667            | 18.605            | +1.938         |
| 1,000,000  | 30,000     | 33.333            | 37.692            | +4.359         |

- For lower and medium event volumes (up to 300,000 operations), the observed time is still close to the expected time.
- As we can see from 300000 operations onwards we see a significant difference of more than 1 second.
