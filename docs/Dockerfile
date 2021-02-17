FROM python

ADD ./requirements.txt ./run-documentation.sh  /

RUN pip install mkdocs mkdocstrings mkdocs-material

ENV PYTHONPATH=/wazuh-qa/deps/wazuh_testing
RUN pip install -r requirements.txt 

ENTRYPOINT ["bash","/run-documentation.sh"] 

