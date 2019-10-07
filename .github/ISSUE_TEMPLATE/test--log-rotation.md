---
name: 'Test: Log rotation'
about: Test suite for log rotation.
title: ''
labels: ''
assignees: ''

---

# Log rotation

| Version | Revision |
| --- | --- |
| x.y.z | rev |

The rotated filenames will have the following format: `ossec-TAG-DAY[-COUNTER].FORMAT.[GZ]`.

`TAGS`: `logs` (for internal logs), `alerts` (for alerts logs) or `archive` (for archives logs).

`DAY`: this will indicate the last day of the logs in the rotated file.

`COUNTER`: from the second rotation (of the same day) on, the filename will be aded a counter (the second one will be `001`).

`FORMAT`: `log` or `json`.

`GZ`: if the option `compress` is active the log will be compressed.

This format must match in every test.

## Summary
- [ ] ROT001
- [ ] ROT002
- [ ] ROT003
- [ ] ROT004
- [ ] ROT005

## ROT001

**Short description**

Wazuh must be capable of rotate logs by interval.

**Category**

Log rotation

**Subcategory**

Interval rotation

**Description**

Wazuh must rotate logs by the interval specified in the configuration. 
It'll accept subdivisions of a day (hours, minutes) or a specific day of the week. For example, it accepts `45m` as `schedule` but `27m` is not a valid value (a day can't be divided in intervals of 27 minutes).
If a specific day of the week is specified the log will be rotated at `00:00` of that day.

**Configuration sample**

``` XML
  <logging>
    <log>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>10m</schedule>
        <compress>yes</compress>
      </rotation>
    </log>
    <alerts>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>4h</schedule>
        <compress>no</compress>
      </rotation>
    </alerts>
    <archives>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>monday</schedule>
        <compress>yes</compress>
      </rotation>
    </archives>
  </logging>
```

**Min/Max compatible versions**
3.12.0 - Current

**Expected files**
Wazuh will rotate the specific log every scheduled (as if the first rotation is at `00:00`) interval.

**Use cases**
The following use cases should be tested:
- [ ] The next rotation is scheduled for this day.
- [ ] The next rotation is scheduled for a day of this/next week  (only with day week `schedule`).
- [ ] The next rotation is scheduled for the first day (or after) of the next month (only with day week `schedule`).
- [ ] The next rotation is scheduled for the first day (or after) of the next year (only with day week `schedule`).

## ROT002

**Short description**

Wazuh must be capable of rotate logs by size.

**Category**

Log rotation

**Subcategory**

Size rotation

**Description**

Wazuh must rotate logs when they grow bigger than `max_size` (indicated the configuration). 
It'll accept bytes (`B`), kilobytes (`K`), megabytes (`M`) and gigabytes (`G`) as value. The minimum value is `1M`.

**Configuration sample**

``` XML
  <logging>
    <log>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <max_size>1M</max_size>
        <compress>yes</compress>
      </rotation>
    </log>
    <alerts>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <max_size>1M</max_size>
        <compress>no</compress>
      </rotation>
    </alerts>
    <archives>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <max_size>1M</max_size>
        <compress>yes</compress>
      </rotation>
    </archives>
  </logging>
```

**Min/Max compatible versions**
3.12.0 - Current

**Expected files**
Wazuh will rotate the specific log every time it grows bigger than `max_size`.

**Use cases**
The following use cases should be tested:
- [ ] The next rotation is scheduled for this day.
- [ ] The next rotation is scheduled for a day of this/next week  (only with day week `schedule`).
- [ ] The next rotation is scheduled for the first day (or after) of the next month (only with day week `schedule`).
- [ ] The next rotation is scheduled for the first day (or after) of the next year (only with day week `schedule`).
- [ ] Several days between a rotation and the next.

## ROT003

**Short description**

Wazuh must be capable of rotate logs by interval or size (combination).

**Category**

Log rotation

**Subcategory**

Interval/maximum size rotation

**Description**

Wazuh must be capable of combine size or interval rotation.

**Configuration sample**

``` XML
  <logging>
    <log>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>10m</schedule>
        <max_size>1M</max_size>
        <compress>yes</compress>
      </rotation>
    </log>
    <alerts>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>4h</schedule>
        <max_size>1M</max_size>
        <compress>no</compress>
      </rotation>
    </alerts>
    <archives>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>monday</schedule>
        <max_size>1M</max_size>
        <compress>yes</compress>
      </rotation>
    </archives>
  </logging>
```

**Min/Max compatible versions**
3.12.0 - Current

**Expected files**
Wazuh will rotate the specific log every scheduled (as if the first rotation is at `00:00`) interval. Also, it'll rotate the specific log if it grows bigger than `max_size`.

**Use cases**
The following use cases should be tested:
- [ ] The next rotation happens before the scheduled interval has passed (the log has grown bigger than `max_size`).
- [ ] The next rotation happens before the the log has grown bigger than `max_size` (the scheduled interval has passed).
- [ ] There are several log rotations before the day week schedule arrives (even days before).
- [ ] The log grows bigger than `max_size` after the day week schedule arrives (check what happens if there are no rotated logs in more than one day).

## ROT004

**Short description**

Wazuh must be capable of rotate logs by interval and size (`min_size`).

**Category**

Log rotation

**Subcategory**

Interval/minimum size rotation

**Description**

Wazuh must be capable of rotate logs combining size (`min_size`) and interval rotation. This means that if the scheduled interval has passed but the file is not bigger than `min_size` the log won't be rotated.

**Configuration sample**

``` XML
  <logging>
    <log>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>10m</schedule>
        <min_size>1M</min_size>
        <compress>yes</compress>
      </rotation>
    </log>
    <alerts>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>4h</schedule>
        <min_size>1M</min_size>
        <compress>no</compress>
      </rotation>
    </alerts>
    <archives>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>monday</schedule>
        <min_size>1M</min_size>
        <compress>yes</compress>
      </rotation>
    </archives>
  </logging>
```

**Min/Max compatible versions**
3.12.0 - Current

**Expected files**
Wazuh will rotate the specific log every scheduled (as if the first rotation is at `00:00`) interval only if the log has grown bigger than `min_size`.
It will also rotate if the log grows bigger than `min_size` after the scheduled interval has passed.

**Use cases**
The following use cases should be tested:
- [ ] The log grows bigger than `min_size` after the `schedule` interval has passed (rotation by size).
- [ ] The log grows bigger than `min_size` before the `schedule` interval has passed (rotation by interval).
- [ ] The log grows bigger than `min_size` after the `schedule` interval has passed (rotation by size). Next day/s.
- [ ] The log grows bigger than `min_size` after the `schedule` interval has passed (rotation by size). Next month/s.
- [ ] The log grows bigger than `min_size` after the `schedule` interval has passed (rotation by size). Next year/s.

## ROT005

**Short description**

Wazuh must be capable of rotate empty logs.

**Category**

Log rotation

**Subcategory**

Empty log rotation

**Description**

Wazuh must rotate logs even if they're empty. This only has to be tested with `schedule` rotation (this use case is not applicable to rotation by size).

**Configuration sample**

``` XML
  <logging>
    <log>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>1m</schedule>
        <compress>yes</compress>
      </rotation>
    </log>
    <alerts>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>1m</schedule>
        <compress>no</compress>
      </rotation>
    </alerts>
    <archives>
      <enabled>yes</enabled>
      <format>json,plain</format>
      <rotation>
        <enabled>yes</enabled>
        <schedule>1m</schedule>
        <compress>yes</compress>
      </rotation>
    </archives>
  </logging>
```

**Min/Max compatible versions**
3.12.0 - Current

**Expected files**
In order to test this we must ensure that the specific log is empty (and empty it if not, before the rotation happens).
The rotated file must be empty.

