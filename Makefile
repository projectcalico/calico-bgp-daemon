###############################################################################
# The build architecture is select by setting the ARCH variable.
# For example: When building on ppc64le you could use ARCH=ppc64le make <....>.
# When ARCH is undefined it defaults to amd64.
ARCH?=amd64
ifeq ($(ARCH),amd64)
        ARCHTAG?=
endif

ifeq ($(ARCH),ppc64le)
        ARCHTAG:=-ppc64le
endif

CALICO_BUILD?=calico/go-build$(ARCHTAG)
SRC_FILES=$(shell find . -type f -name '*.go')
GOBGPD_VERSION?=$(shell git describe --tags --dirty)
CONTAINER_NAME?=calico/gobgpd$(ARCHTAG)
PACKAGE_NAME?=github.com/projectcalico/calico-bgp-daemon
LOCAL_USER_ID?=$(shell id -u $$USER)
DIST=dist/$(ARCH)

# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor: glide.yaml
	mkdir -p $(HOME)/.glide
	# To build without Docker just run "glide install -strip-vendor"
	docker run --rm \
    -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
    -v $(HOME)/.glide:/home/user/.glide:rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
      glide install -strip-vendor'

binary: $(DIST)/calico-bgp-daemon

$(DIST)/gobgp:
	mkdir -p $(@D)
	docker run --rm -v $(CURDIR)/$(DIST):/go/bin \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-e ARCH=$(ARCH) \
	$(CALICO_BUILD) sh -c '\
		go get -u github.com/golang/dep/cmd/dep && \
		go get github.com/osrg/gobgp || \
		cd /go/src/github.com/osrg/gobgp && dep ensure && \
		go get -v github.com/osrg/gobgp/gobgp'
	rm -f $(DIST)/dep

$(DIST)/calico-bgp-daemon: $(SRC_FILES) vendor
	mkdir -p $(@D)
	go build -v -o $(DIST)/calico-bgp-daemon \
	-ldflags "-X main.VERSION=$(GOBGPD_VERSION) -s -w" main.go ipam.go k8s.go

build-containerized: clean vendor $(DIST)/gobgp
	mkdir -p $(DIST)
	docker run --rm \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
	-v $(CURDIR)/$(DIST):/go/src/$(PACKAGE_NAME)/$(DIST) \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-e ARCH=$(ARCH) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			make binary'

$(CONTAINER_NAME): build-containerized
	docker build -t $(CONTAINER_NAME) -f Dockerfile$(ARCHTAG) .

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)
	$(MAKE) $(CONTAINER_NAME) 
	# Check that the version output appears on a line of its own (the -x option to grep).
	# Tests that the "git tag" makes it into the binary. Main point is to catch "-dirty" builds
	@echo "Checking if the tag made it into the binary"
	docker run --rm $(CONTAINER_NAME) -v | grep -x $(VERSION) || (echo "Reported version:" `docker run --rm $(CONTAINER_NAME) -v` "\nExpected version: $(VERSION)" && exit 1)
	docker tag $(CONTAINER_NAME) $(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):latest

	@echo "Now push the tag and images. Then create a release on Github and attach the $(DIST)/gobgpd and $(DIST)/gobgp binaries"
	@echo "git push origin $(VERSION)"
	@echo "docker push $(CONTAINER_NAME):$(VERSION)"
	@echo "docker push quay.io/$(CONTAINER_NAME):$(VERSION)"
	@echo "docker push $(CONTAINER_NAME):latest"
	@echo "docker push quay.io/$(CONTAINER_NAME):latest"

clean:
	rm -rf vendor
	rm -rf $(DIST)
