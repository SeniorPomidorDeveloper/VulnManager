FROM ubuntu:24.04

ARG DEB

COPY ${DEB} /tmp/vulnmanager-ingest.deb

RUN apt-get update \
    && apt-get install -y --no-install-recommends /tmp/vulnmanager-ingest.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/vulnmanager-ingest.deb

USER nobody

EXPOSE 8080

ENTRYPOINT ["/usr/bin/vulnmanager-ingest"]
