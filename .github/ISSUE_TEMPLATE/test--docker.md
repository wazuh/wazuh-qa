---
name: 'Test: docker'
about: Test suite for the integration with docker.
title: ''
labels: ''
assignees: ''

---

# docker test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

- [ ] Enable / disable daemon.
- [ ] Check invalid configuration. The module should log a warning and continue.
- [ ] Run the docker integration and fire alerts when:
    - [ ] Create/start/stop/pause/resume/destroy/delete containers.
    - [ ] Run a command with `exec` in a container.
    - [ ] Open a shell session in a container.
    - [ ] Share files between containers and the host.
    - [ ] Create/destroy a volume.
    - [ ] Export a filesystem.
    - [ ] Create/delete a network.
    - [ ] Create/delete a service.