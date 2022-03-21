From ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNING_ON_DOCKER_CONTAINER=true

RUN apt-get -q update && \
    apt-get install -y \
        curl \
        python \
        python3 \
        sshpass \
        python3-pip \
        python3-setuptools

ADD https://raw.githubusercontent.com/wazuh/wazuh-qa/master/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /tmp/requirements.txt --ignore-installed

RUN mkdir /wazuh_qa_ctl

COPY ./entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod 755 /usr/bin/entrypoint.sh

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
