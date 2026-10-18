FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends debhelper dpkg-dev \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -m 1777 /w
