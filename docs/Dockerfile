FROM python

COPY ../requirements.txt /
COPY ./run-documentation.sh /usr/bin

RUN pip install mkdocs mkdocstrings mkdocs-material
RUN pip install -r requirements.txt

ENTRYPOINT ["/usr/bin/run-documentation.sh"] 
