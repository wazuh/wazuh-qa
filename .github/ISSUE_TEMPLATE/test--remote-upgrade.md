---
name: 'Test: Remote upgrades'
about: Test suite for remote upgrades.
title: ''
labels: ''
assignees: ''

---

# Remote upgrade test (WPK)

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Remote upgrades (WPK)

- [ ] Upgrade an agent remotely (Linux and Windows) and check the _upgrade.log_  (UDP)
- [ ] Upgrade an agent remotely (Linux and Windows) and check the _upgrade.log_  (TCP)
- [ ] Upgrade an agent whose register IP is different from its reported IP.
- [ ] Send a WPK with different values of `chunk_size`.
- [ ] Upgrade an agent with a custom WPK (`-f` option).
- [ ] Downgrade an agent (`-F` option).
- [ ] Upgrade an agent without CA verification.