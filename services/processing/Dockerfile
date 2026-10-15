FROM ubuntu:24.04

ARG DEB

COPY ${DEB} /tmp/vulnmanager-processing.deb

RUN apt-get update \
    && apt-get install -y --no-install-recommends /tmp/vulnmanager-processing.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/vulnmanager-processing.deb

USER nobody

EXPOSE 8082

ENTRYPOINT ["/usr/bin/vulnmanager-processing"]
