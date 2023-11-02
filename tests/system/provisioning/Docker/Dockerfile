# Use dontpanicat/debian image to bypass https://github.com/wazuh/wazuh/issues/19829
FROM dontpanicat/debian:latest

# Set environment variables for non-interactive package installation
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update --allow-releaseinfo-change

# Update the package repositories and install essential packages in one step
RUN apt-get update && apt-get install -y \
    git \
    make \
    cmake \
    libc6-dev \
    curl \
    policycoreutils \
    automake \
    autoconf \
    libtool \
    libssl-dev \
    build-essential \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev

# Download and build GCC 10.3.0
WORKDIR /tmp
RUN curl -s https://ftp.gnu.org/gnu/gcc/gcc-10.3.0/gcc-10.3.0.tar.xz | tar -xJ
RUN mkdir build && cd build
RUN ./gcc-10.3.0/configure --prefix=/usr/local \
                        --disable-dependency-tracking \
                        --disable-nls \
                        --disable-multilib \
                        --enable-default-pie \
                        --enable-languages=c,c++
RUN make -j$(nproc)
RUN make install

# Cleanup unnecessary files and links
RUN rm -rf /usr/bin/gcc && rm /usr/bin/g++
RUN ln -s /usr/local/bin/gcc /usr/bin/gcc && ln -s /usr/local/bin/g++ /usr/bin/g++

RUN rm -rf /tmp/*

# Set up an entry point to keep the container running
CMD ["tail", "-f", "/dev/null"]
