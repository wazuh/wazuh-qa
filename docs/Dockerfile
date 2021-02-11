FROM python

COPY --chown=1000:1000 ./requirements.txt ./
COPY --chown=1000:1000 ./run-documentation.sh ./

# RUN chmod +x ./run-documentation.sh

RUN pip install mkdocs
RUN pip install mkdocstrings
RUN pip install mkdocs-material

RUN export PYTHONPATH=/wazuh-qa/deps/wazuh_testing
RUN pip install -r requirements.txt 


CMD ["bash","/run-documentation.sh"]

