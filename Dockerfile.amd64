FROM scratch

LABEL maintainer="tom@tigera.io"

ADD bin/amd64/gobgp /gobgp
ADD bin/amd64/calico-bgp-daemon /calico-bgp-daemon

ENTRYPOINT ["/calico-bgp-daemon"]
