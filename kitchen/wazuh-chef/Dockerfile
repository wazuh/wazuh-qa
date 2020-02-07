FROM ruby

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
    cd $HOME/wazuh-qa && \
    git checkout devel && \
    cd $HOME/wazuh-qa/kitchen/wazuh-chef/manager/files/ && \
    bundle install

RUN git clone https://github.com/rshad/kitchen-docker && \
    cd kitchen-docker && \
    git checkout fix-docker-image-deletion && \
    git pull origin fix-docker-image-deletion

RUN rm -rf /usr/local/bundle/gems/kitchen-docker-2.9.0/* && \
    cp -rf kitchen-docker/* /usr/local/bundle/gems/kitchen-docker-2.9.0/

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py

RUN pip install pytest && pip install testinfra && pip install paramiko

# Standard SSH port
EXPOSE 22