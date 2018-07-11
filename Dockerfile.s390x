FROM scratch

LABEL maintainer="tom@tigera.io"

ADD bin/s390x/gobgp /gobgp
ADD bin/s390x/calico-bgp-daemon /calico-bgp-daemon

ENTRYPOINT ["/calico-bgp-daemon"]
