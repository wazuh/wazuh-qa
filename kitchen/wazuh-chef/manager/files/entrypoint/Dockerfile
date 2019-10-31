FROM ruby

CMD tail -f /dev/null

COPY entrypoint.sh /usr/local/bin/

RUN chmod 777 /usr/local/bin/entrypoint.sh \
    && ln -s /usr/local/bin/entrypoint.sh /

ENTRYPOINT ["entrypoint.sh"]

RUN apt-get update && apt install docker.io git curl wget -y

RUN apt-get update

RUN gem install kitchen-docker && \
    gem install rbnacl && \
    gem install rbnacl-libsodium && \
    gem install bcrypt_pbkdf && \
    gem install berkshelf && \
    gem install httpclient

RUN cd $HOME && \
    git clone https://github.com/wazuh/wazuh-qa.git && \
    cd $HOME/wazuh-qa/kitchen/wazuh-chef/manager/files/ && \
    bundle install

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py

RUN pip install pytest && pip install testinfra && pip install paramiko

# Standard SSH port
EXPOSE 22