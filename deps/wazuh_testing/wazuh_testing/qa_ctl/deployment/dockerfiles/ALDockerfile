FROM amazonlinux:2.0.20200602.0

RUN yum update -y && \
    yum install -y \
        openssh-server \
        nano \
        openssl \
        sudo \
        gcc \
        git \
        python3 \
        python3-devel

ADD entrypoint.sh /usr/bin/entrypoint.sh
ADD https://raw.githubusercontent.com/wazuh/wazuh-qa/master/requirements.txt /tmp/requirements.txt

RUN pip3 install --upgrade pip && \
    pip install -r /tmp/requirements.txt

RUN useradd wazuh && \
    echo 'wazuh:wazuh' | chpasswd && \
    echo "wazuh ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN echo 'root:root' | chpasswd

RUN sed -i 's/#SyslogFacility AUTHPRIV/SyslogFacility DAEMON/g' /etc/ssh/sshd_config && \
    sed -ri 's/.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config && \
    sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config && \
    mkdir /var/run/sshd && \
    mkdir -p /home/wazuh && \
    chmod +x /usr/bin/entrypoint.sh && \
    echo 'Defaults:root !requiretty' >> /etc/sudoers

EXPOSE 22/tcp 1514/udp 1514/tcp 1515/tcp 1516/tcp 514/udp 514/tcp 55000/tcp

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
