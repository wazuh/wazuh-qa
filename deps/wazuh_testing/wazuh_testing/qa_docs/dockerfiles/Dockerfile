FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNING_ON_DOCKER_CONTAINER=true

# install packages
RUN apt-get update && \
    apt-get install -y \
    git \
    python \
    python3-pip \
    curl \
    npm \
    apt-transport-https \
    lsb-release \
    gnupg

# install ES
RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - && \
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list && \
    apt update && \
    apt install -y elasticsearch

# install wazuh manager
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install wazuh-manager

WORKDIR /
RUN git clone https://github.com/wazuh/wazuh-qa
WORKDIR /wazuh-qa/
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install -r requirements.txt --ignore-installed

# Install the QA framework
WORKDIR /wazuh-qa/deps/wazuh_testing
RUN python3 setup.py install

# Install search-ui deps
WORKDIR /usr/local/lib/python3.8/dist-packages/wazuh_testing-*/wazuh_testing/qa_docs/search_ui
RUN npm install

# Limit ES RAM
RUN echo "-Xms1g" >> /etc/elasticsearch/jvm.options && \
    echo "-Xmx1g" >> /etc/elasticsearch/jvm.options && \
    # Disable xpack to prevent ES showing security warning
    echo "xpack.security.enabled: false" >> /etc/elasticsearch/elasticsearch.yml

# copy entrypoint and grant permission
COPY ./entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod 755 /usr/bin/entrypoint.sh

ENTRYPOINT [ "/usr/bin/entrypoint.sh" ]