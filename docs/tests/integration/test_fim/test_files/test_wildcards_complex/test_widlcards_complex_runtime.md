# Test complex wildcards
In every scan, FIM looks for any new folder that matches a configured wildcard expression. This test checks this
functionality using complex wildcards expression (expressions that may match a given subdirectory, all subdirectories, etc).

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 1503s |
| 1 | Windows | 756s |

## Test logic
The test will configure wildcards expressions and will create an empty folder. Once that FIM has started and the
baseline scan is completed, the test will create folders that may match a configured expression and will wait until
the wildcards are expanded again (in the next scan). Once the wildcards are reloaded, the test will create, modify and
delete files inside those folders. The test will wait for events of a folder only if it matches a configured expression.
## Execution result

```

```

## Code documentation

::: tests.integration.test_fim.test_files.test_wildcards_complex.test_wildcards_complex_runtime
