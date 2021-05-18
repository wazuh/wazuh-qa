# Test execd restart

This test checks if the Active Response script called `restart-wazuh` is executed correctly when configured.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 0 | Linux/Windows | 10s | [test_active_response/test_execd/test_execd_restart.py]|

## Test logic

- Check Active Response enabled in ossec logs and AR logs.
- If expected success check shutdown message.
- If not, check error log "Invalid input format"

## Code documentation

::: tests.integration.test_active_response.test_execd.test_execd_restart
