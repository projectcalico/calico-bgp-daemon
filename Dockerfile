FROM alpine:3.4

MAINTAINER Gunjan Patel <gunjan@tigera.io>

ADD dist/amd64/gobgp /gobgp
ADD dist/amd64/calico-bgp-daemon /calico-bgp-daemon

ENTRYPOINT ["/calico-bgp-daemon"]
