# Test execd firewall drop
This test check that Active Response script called 'firewall-drop' is executed correctly when configured.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 0 | Linux | 00:00:11 | [test_active_response/test_execd/test_execd_firewall_drop.py]|

## Test logic

- Check Active Response enabled in ossec logs and AR logs.
- If expected success check if the IP was added/removed in iptables.
- If not, check error log "Invalid input format"

## Code documentation

<!-- ::: tests.integration.test_active_response.test_execd.test_execd_firewall_drop -->
