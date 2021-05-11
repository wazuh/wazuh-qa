# Overview 

## Description

These tests will check if commands with different characteristics are executed correctly. 
It will also be checked that the info and debug lines are written in the logs when executing these commands.

The verification will be performed by analyzing the logs and checking the lines that indicate that 
the command has been executed correctly.

## Objective

Confirm that the different options for command monitoring and configuration work and are correctly loaded.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 52 | 6m17s |

## List of command monitoring tests
  
- **[Test command execution](test_command_execution.md)**: Check if the Wazuh runs correctly by executing 
  different commands with special characteristics.
  
- **[Test command execution freq](test_command_execution_freq.md)**: Check if the Wazuh run commands correctly with 
  the specified command monitoring option `frequency`.

