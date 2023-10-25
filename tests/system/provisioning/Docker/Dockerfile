FROM ubuntu:jammy

# Update the package repositories and install essential packages
RUN apt-get update && apt-get install -y \
    python3 \
    gcc \
    g++ \
    make \
    cmake \
    libc6-dev \
    curl \
    policycoreutils \
    automake \
    autoconf \
    libtool \
    sqlite3 \
    libssl-dev \
    apt-utils \
    apt-transport-https \
    openssh-server \
    vim \
    git \
    wget \
    unzip \
    binutils \
    gnupg \
    lsb-release

# Set up an entry point to keep the container running
ENTRYPOINT ["tail", "-f", "/dev/null"]
