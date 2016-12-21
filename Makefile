
CALICO_BUILD?=calico/go-build
SRC_FILES=$(shell find . -type f -name '*.go')
GOBGPD_VERSION?=$(shell git describe --tags --dirty)

vendor:
	docker run --rm -v ${PWD}:/go/src/github.com/projectcalico/calico-bgp-daemon:rw --entrypoint=sh \
        dockerepo/glide -c ' \
	cd /go/src/github.com/projectcalico/calico-bgp-daemon; \
	glide install -strip-vcs -strip-vendor --cache; \
	chown $(shell id -u):$(shell id -u) -R vendor'

binary: dist/gobgpd

dist/gobgp:
	mkdir -p $(@D)
	docker run --rm -v `pwd`/dist:/code golang:1.7 \
	sh -c 'go get github.com/osrg/gobgp/gobgp && cp /go/bin/gobgp /code && chown $(shell id -u):$(shell id -g) /code/gobgp'

dist/gobgpd: $(SRC_FILES) vendor
	mkdir -p $(@D)
	go build -v -o dist/calico-bgp-daemon \
	-ldflags "-X main.VERSION=$(GOBGPD_VERSION) -s -w" main.go

build-containerized: clean vendor dist/gobgp
	mkdir -p dist
	docker run --rm \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-bgp-daemon \
	-v ${PWD}/dist:/go/src/github.com/projectcalico/calico-bgp-daemon/dist \
	-e LOCAL_USER_ID=`id -u $$USER` \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/github.com/projectcalico/calico-bgp-daemon && \
			make binary'

release: clean build-containerized

clean:
	rm -rf vendor
	rm -rf dist
