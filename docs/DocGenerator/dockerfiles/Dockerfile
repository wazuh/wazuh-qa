FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    git \
    python \
    python3-pip \
    curl \
    npm

# cloning and installing qa reqs
RUN git clone https://github.com/wazuh/wazuh-qa.git && \
    pip install -r wazuh-qa/requirements.txt && \
    python3 wazuh-qa/deps/wazuh_testing/setup.py install && \
    pip install -r wazuh-qa/docs/DocGenerator/requirements.txt

# install ES
RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - && \
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list && \
    apt update && \
    apt install -y default-jre && \
    apt install -y default-jdk && \
    apt install -y elasticsearch

# get test doc output
WORKDIR wazuh-qa/docs/DocGenerator/
RUN git checkout 1797-docker-deployment && \
    pip install -r requirements.txt && \
    python3 DocGenerator.py

WORKDIR Search-UI/
RUN npm install --save-dev typescript
WORKDIR ../

# index jsons and launch SearchUI and wait that ES is up
CMD service elasticsearch start && \
    sleep 8 && \
    python3 DocGenerator.py -l qa-doc