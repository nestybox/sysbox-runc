ARG GO_VERSION=1.16
ARG BATS_VERSION=v1.2.1
ARG UMOCI_VERSION=v0.4.6

FROM golang:${GO_VERSION}-bullseye
ARG DEBIAN_FRONTEND=noninteractive

RUN echo 'deb https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_11/ /' > /etc/apt/sources.list.d/criu.list \
    && wget -nv https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_11/Release.key -O- | apt-key add - \
    && echo 'deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_11/ /' > /etc/apt/sources.list.d/skopeo.list \
    && wget -nv https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/Debian_11/Release.key -O- | apt-key add - \
    && dpkg --add-architecture armel \
    && dpkg --add-architecture armhf \
    && dpkg --add-architecture arm64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        criu \
        crossbuild-essential-arm64 \
        crossbuild-essential-armel \
        crossbuild-essential-armhf \
        curl \
        gawk \
        iptables \
        jq \
        kmod \
        libseccomp-dev \
        libseccomp-dev:arm64 \
        libseccomp-dev:armel \
        libseccomp-dev:armhf \
        libseccomp2 \
        lsb-release \
        pkg-config \
        python2-minimal \
        skopeo \
        sudo \
        uidmap \
    && apt-get clean \
    && rm -rf /var/cache/apt /var/lib/apt/lists/* /etc/apt/sources.list.d/*.list

# Add a dummy user for the rootless integration tests. While runC does
# not require an entry in /etc/passwd to operate, one of the tests uses
# `git clone` -- and `git clone` does not allow you to clone a
# repository if the current uid does not have an entry in /etc/passwd.
RUN useradd -u1000 -m -d/home/rootless -s/bin/bash rootless

# install bats
ARG BATS_VERSION
RUN cd /tmp \
    && git clone https://github.com/bats-core/bats-core.git \
    && cd bats-core \
    && git reset --hard "${BATS_VERSION}" \
    && ./install.sh /usr/local \
    && rm -rf /tmp/bats-core

# install umoci
ARG UMOCI_VERSION
RUN curl -o /usr/local/bin/umoci -fsSL https://github.com/opencontainers/umoci/releases/download/${UMOCI_VERSION}/umoci.amd64 \
    && chmod +x /usr/local/bin/umoci

# install debug tools
RUN go get github.com/go-delve/delve/cmd/dlv \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    psmisc

WORKDIR /root/nestybox/sysbox-runc

# setup a playground for us to spawn containers in
COPY tests/integration/multi-arch.bash tests/integration/
ENV ROOTFS /busybox
RUN mkdir -p "${ROOTFS}"
RUN . tests/integration/multi-arch.bash \
    && curl -fsSL `get_busybox` | tar xfJC - "${ROOTFS}"

ENV DEBIAN_ROOTFS /debian
RUN mkdir -p "${DEBIAN_ROOTFS}"
RUN . tests/integration/multi-arch.bash \
    && get_and_extract_debian "$DEBIAN_ROOTFS"
