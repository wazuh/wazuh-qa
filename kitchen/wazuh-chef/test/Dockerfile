FROM centos:7
ENV container docker
RUN yum clean all
RUN yum install -y sudo openssh-server openssh-clients which curl
RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N ''
RUN if ! getent passwd kitchen; then                 useradd -d /home/kitchen -m -s /bin/bash -p '*' kitchen;               fi
RUN echo "kitchen ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo "Defaults !requiretty" >> /etc/sudoers
RUN mkdir -p /home/kitchen/.ssh
RUN chown -R kitchen /home/kitchen/.ssh
RUN chmod 0700 /home/kitchen/.ssh
RUN touch /home/kitchen/.ssh/authorized_keys
RUN chown kitchen /home/kitchen/.ssh/authorized_keys
RUN chmod 0600 /home/kitchen/.ssh/authorized_keys
RUN mkdir -p /run/sshd
RUN echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDM6ET6P6A7F7bw4gpzfFPEGFb7zJ+s1y16ubfJumGpeawiKcpQ1BT4NgIJR2MKuQA/zPT8SvE0AsPtMRqA02eUXk/w/3tRMJzgsxxNGwhQfhGKpqyBVjazG1x3WenQHXSyeXcRU8GhXSWaLJmnu+U959JTxlJAg+iAX+803ymxWsjs3RIpJEfHhYSY/Hn+UQEi0CdAuQ5M6PBtuf5kdpnJa3Kojl5MeSPL/uoLE9Kv6hdH1pdqWmxBZnj7SAuELIYCL+2A1fNGkbs3PiMaTvfQhaQc2k05wIfdJ98nDv5TTQ8cYCp2AWL+8n2apZDHxykD8vmbwaVRhVSUtSuAKsZZ kitchen_docker_key >> /home/kitchen/.ssh/authorized_keys
EXPOSE 1515/tcp
EXPOSE 1515/udp
RUN yum install -y openssl
