# Overview 

## Description

These tests ensure age option work as expected, ignoring files that have not been  modified for a time greater than age 
value using current date, even if datetime of the system changed while logcollector is running.

## Objective

Confirm that the age option works properly.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 45 | 2m40s |

## List of configuration tests

- **[Test age basic](test_age_basic.md)**:  Check that those files that have not been modified for a time greater 
  than age value, are ignored for logcollector. Otherwise, files should not be ignored. Also, it checks logcollector 
  detect modification time changes in monitored files and catch new logs from ignored and not ignored files.

- **[Test age datetime changed](test_age_datetime_changed.md)**: Ensure that when date of the system change 
  logcollector use properly age value, ignoring files that have not been modified for a time greater than age 
  value using current date.
