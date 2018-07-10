FROM scratch

LABEL maintainer="tom@tigera.io"

ADD bin/arm64/gobgp /gobgp
ADD bin/arm64/calico-bgp-daemon /calico-bgp-daemon

ENTRYPOINT ["/calico-bgp-daemon"]
