
CALICO_BUILD?=calico/go-build
SRC_FILES=$(shell find . -type f -name '*.go')
GOBGPD_VERSION?=$(shell git describe --tags --dirty)
CONTAINER_NAME?=calico/gobgpd

vendor:
	docker run --rm -v ${PWD}:/go/src/github.com/projectcalico/calico-bgp-daemon:rw --entrypoint=sh \
        dockerepo/glide -c ' \
	cd /go/src/github.com/projectcalico/calico-bgp-daemon; \
	glide install -strip-vcs -strip-vendor --cache; \
	chown $(shell id -u):$(shell id -u) -R vendor'

binary: dist/gobgpd

dist/gobgp:
	mkdir -p $(@D)
	docker run --rm -v `pwd`/dist:/code $(CALICO_BUILD) \
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

$(CONTAINER_NAME): build-containerized
	docker build -t $(CONTAINER_NAME) .

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)
	$(MAKE) $(CONTAINER_NAME) 
	# Check that the version output appears on a line of its own (the -x option to grep).
	# Tests that the "git tag" makes it into the binary. Main point is to catch "-dirty" builds
	@echo "Checking if the tag made it into the binary"
	docker run --rm calico/gobgpd -v | grep -x $(VERSION) || (echo "Reported version:" `docker run --rm calico/gobgpd -v` "\nExpected version: $(VERSION)" && exit 1)
	docker tag calico/gobgpd calico/gobgpd:$(VERSION)
	docker tag calico/gobgpd quay.io/calico/gobgpd:$(VERSION)
	docker tag calico/gobgpd quay.io/calico/gobgpd:latest

	@echo "Now push the tag and images. Then create a release on Github and attach the dist/gobgpd and dist/gobgp binaries"
	@echo "git push origin $(VERSION)"
	@echo "docker push calico/gobgpd:$(VERSION)"
	@echo "docker push quay.io/calico/gobgpd:$(VERSION)"
	@echo "docker push calico/gobgpd:latest"
	@echo "docker push quay.io/calico/gobgpd:latest"

clean:
	rm -rf vendor
	rm -rf dist
