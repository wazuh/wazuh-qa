FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive

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

RUN mkdir tests

WORKDIR tests

# cloning parsed tests
RUN git clone https://github.com/wazuh/wazuh-qa.git

WORKDIR wazuh-qa

ARG BRANCH

RUN git checkout ${BRANCH}

WORKDIR /

# cloning and installing qa reqs
RUN git clone https://github.com/wazuh/wazuh-qa.git

WORKDIR wazuh-qa/deps/wazuh_testing/

RUN git checkout 1864-qa-docs-fixes && \
    pip install -r ../../requirements.txt && \
    pip install -r wazuh_testing/qa_docs/requirements.txt && \
    python3  setup.py install

# start services, parse some tests and launch the api
CMD service elasticsearch start && \
    service wazuh-manager start && \
    sleep 8 && \
    qa-docs -I /tests/wazuh-qa/tests --types integration && \
    qa-docs -I /tests/wazuh-qa/tests -il qa-docs
