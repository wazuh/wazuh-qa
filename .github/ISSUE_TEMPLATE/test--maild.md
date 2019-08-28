---
name: 'Test: Maild'
about: Test suite for Maild.
title: ''
labels: ''
assignees: ''

---

# Maild test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Send reports

- [ ] Configure the mail alerts and receive an alert in your email.
- [ ] Receive FIM alerts (using the alerts.json as source file).
- [ ] Receive alerts from the alerts.json including the field full_log.
- [ ] Receive alerts from the alerts.json without the field full_log.

## Configuration

- [ ] Check the typical settings such as `email_reply_to`.
- [ ] Test the option `email_log_source` since Wazuh v3.8.0.

## Filters

- [ ] Check filters: `email_maxperhour`, `level`, `group`, etc...
