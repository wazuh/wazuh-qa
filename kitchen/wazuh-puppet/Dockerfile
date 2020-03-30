FROM ubuntu:18.04


# Global required packages
RUN apt-get update -qq -y && \
    apt-get upgrade -qq -y && \
    apt-get install -qq -y \
      build-essential \
      apt-transport-https \
      ca-certificates \
      curl \
      wget \
      software-properties-common \
      dirmngr \
      libreadline-dev \
      libssl-dev \
      lsb-release \
      puppet \
      rbenv \
      ruby \
      ruby-dev \
      rubygems \
      sudo \
      systemd \
      systemd-sysv \
      wget \
      zlib1g-dev


# PDK dependencies
RUN wget https://apt.puppet.com/puppet-tools-release-bionic.deb && \
    dpkg -i puppet-tools-release-bionic.deb && \
    apt-get update && \
    apt-get install -y pdk


# docker-ce related installation tasks.
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" && \
    apt update -qq -y && \
    apt-cache policy docker-ce && \
    apt install docker-ce -y


# Required gems.
RUN gem install rake \
      --no-document \
      --quiet && \
    gem install bundler \
      --no-document \
      --quiet && \
    gem install kitchen-docker_cli \
      --no-document \
      --quiet && \
    gem install kitchen-docker -v 2.9.0 \
      --no-document \
      --quiet && \
    gem install kitchen-puppet \
      --no-document \
      --quiet && \
    gem install kitchen-verifier-serverspec \
      --no-document \
      --quiet && \
    gem install librarian-puppet \
      --no-document \
      --quiet && \
    gem install test-kitchen \
      --no-document \
      --quiet && \
    gem install kitchen-goss \
      --no-document \
      --quiet

# Clone wazuh-qa
RUN cd $HOME && \
    git clone https://github.com/wazuh/wazuh-qa.git && \
    cd $HOME/wazuh-qa && \
    git checkout devel && \
    git pull origin devel

# Copy our custom kitchen-docker to the gem folder.
RUN rm -rf /var/lib/gems/2.5.0/gems/kitchen-docker-2.9.0/* && \
    cp -rf $HOME/wazuh-qa/kitchen/kitchen-docker/* /var/lib/gems/2.5.0/gems/kitchen-docker-2.9.0/


# Python Dependencies and Libraries
RUN apt install python3-venv python3-pip -y && \
    python3 -m pip install pytest && \
    python3 -m pip install testinfra && \
    python3 -m pip install paramiko

# Adding systemd compatibility.
VOLUME [ "/sys/fs/cgroup", "/run", "/run/lock" ]

CMD  [ "/lib/systemd/systemd" ]
