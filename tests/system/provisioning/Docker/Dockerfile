# Image based on dontpanicat/debian image to bypass https://github.com/wazuh/wazuh/issues/19829
FROM debian:11.8

# Adding backports to debian
RUN echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list

# Installing libraries
RUN apt-get update -y && \
    apt-get install -y \
        apt-transport-https \
        bash-completion \
        build-essential \
        cron \
        curl \
        git \
        libbz2-dev \
        libdb5.3-dev \
        libgcc1 \
        libstdc++6 \
        libexpat1-dev \
        libffi-dev \
        libgdbm-dev \
        liblzma-dev \
        libncurses5-dev \
        libncursesw5-dev \
        libreadline-dev \
        libssl-dev \
        libsqlite3-dev \
        locales \
        logrotate \
        openssh-server \
        rsyslog \
        vim \
        cmake \
        wget \
        zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Installing Python
RUN wget https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tgz && \
    tar xzf Python-3.10.0.tgz && \
    cd Python-3.10.0 && \
    ./configure --enable-optimizations && \
    make -j && \
    make altinstall && \
    cd .. && \
    ln -s /usr/local/bin/python3.10 /usr/local/bin/python && \
    ln -s /usr/local/bin/pip3.10 /usr/local/bin/pip

RUN rm -rf /Python-3.10.0.tgz && \
    rm -rf /Python-3.10.0

# Set up an entry point to keep the container running
CMD ["tail", "-f", "/dev/null"]
