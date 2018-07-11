FROM scratch

LABEL maintainer="tom@tigera.io"

ADD bin/ppc64le/gobgp /gobgp
ADD bin/ppc64le/calico-bgp-daemon /calico-bgp-daemon

ENTRYPOINT ["/calico-bgp-daemon"]
