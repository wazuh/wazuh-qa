FROM amd64/ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -q update && \
    apt-get -q install -y \
        curl \
        lsb-release \
        apt-transport-https \
        gnupg2 \
        nano \
        python3 \
        python3-pip \
        gcc \
        make \
        zlib1g-dev \
        libssl-dev

COPY ./entrypoint.py /usr/bin/entrypoint.py

EXPOSE 22/tcp 1514/udp 1514/tcp 1515/tcp 1516/tcp 514/udp 514/tcp 55000/tcp

ENTRYPOINT ["python3", "/usr/bin/entrypoint.py"]
