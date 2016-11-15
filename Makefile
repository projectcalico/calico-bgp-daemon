gobgp:
	docker run --rm -v `pwd`:/code golang:1.7 \
	sh -c 'go get github.com/osrg/gobgp/gobgp && cp /go/bin/gobgp /code && chown $(shell id -u):$(shell id -g) /code/gobgp'

vendor:
	docker run --rm -v ${PWD}:/go/src/github.com/projectcalico/calico-bgp-daemon:rw --entrypoint=sh \
        dockerepo/glide -c ' \
	cd /go/src/github.com/projectcalico/calico-bgp-daemon; \
	glide install -strip-vcs -strip-vendor --cache; \
	chown $(shell id -u):$(shell id -u) -R vendor'

calico-bgp-daemon: main.go vendor
	docker run --rm \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-bgp-daemon \
	golang:1.7 bash -c 'cd /go/src/github.com/projectcalico/calico-bgp-daemon/ && go build && chown $(shell id -u):$(shell id -g) -R $@'

release: clean calico-bgp-daemon gobgp

clean:
	rm -rf vendor
	rm -f gobgp
	rm -f calico-bgp-daemon
