FROM python

RUN git clone https://github.com/wazuh/wazuh-qa

WORKDIR /wazuh-qa/deps/wazuh_testing

RUN python3 setup.py install

WORKDIR /wazuh-qa

RUN pip install -r requirements.txt

RUN pip install mkdocs mkdocstrings mkdocs-material

COPY ./run-documentation.sh /usr/bin

ENTRYPOINT ["/usr/bin/run-documentation.sh"]
