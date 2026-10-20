# strongSwan node for the IPsec Tunnelmatch GNS3 lab.
#   docker build -t tunnelmatch-strongswan lab/gns3/strongswan
# Build it on the machine that runs GNS3 (or the GNS3 VM). run.py creates the
# GNS3 docker template "tunnelmatch-strongswan" itself if it does not exist.
# ESP runs in the host kernel (XFRM); GNS3 runs docker nodes privileged.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      strongswan-swanctl charon-systemd libstrongswan-standard-plugins \
      libstrongswan-extra-plugins libcharon-extra-plugins \
      iproute2 iputils-ping procps \
 && rm -rf /var/lib/apt/lists/*
CMD ["/bin/bash"]
