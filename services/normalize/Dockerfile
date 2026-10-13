FROM ubuntu:24.04

ARG DEB

COPY ${DEB} /tmp/vulnmanager-normalize.deb

RUN apt-get update \
    && apt-get install -y --no-install-recommends /tmp/vulnmanager-normalize.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/vulnmanager-normalize.deb

USER nobody

EXPOSE 8081

ENTRYPOINT ["/usr/bin/vulnmanager-normalize"]
