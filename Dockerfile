FROM alpine

MAINTAINER Gunjan Patel <gunjan@tigera.io>

ADD dist/gobgp /gobgp
ADD dist/calico-bgp-daemon /calico-bgp-daemon

ENTRYPOINT ["/calico-bgp-daemon"]
