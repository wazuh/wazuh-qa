FROM qa-docs_base:0.1

RUN mkdir tests

WORKDIR /home/tests

# cloning parsed tests
RUN git clone https://github.com/wazuh/wazuh-qa.git

WORKDIR /home/tests/wazuh-qa

ARG BRANCH

RUN git checkout ${BRANCH}

WORKDIR /home/wazuh-qa/deps/wazuh_testing

# start services, parse some tests and launch the api
CMD service elasticsearch start && \
    service wazuh-manager start && \
    qa-docs -I /home/tests/wazuh-qa/tests --types integration && \
    qa-docs -I /home/tests/wazuh-qa/tests -il qa-docs
