
CALICO_BUILD?=calico/go-build
SRC_FILES=$(shell find . -type f -name '*.go')
GOBGPD_VERSION?=$(shell git describe --tags --dirty)
CONTAINER_NAME?=calico/gobgpd
PACKAGE_NAME?=github.com/projectcalico/calico-bgp-daemon
LOCAL_USER_ID?=$(shell id -u $$USER)

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

binary: dist/calico-bgp-daemon

dist/gobgp:
	mkdir -p $(@D)
	docker run --rm -v $(CURDIR)/dist:/go/bin \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	$(CALICO_BUILD) go get -v github.com/osrg/gobgp/gobgp

dist/calico-bgp-daemon: $(SRC_FILES) vendor
	mkdir -p $(@D)
	go build -v -o dist/calico-bgp-daemon \
	-ldflags "-X main.VERSION=$(GOBGPD_VERSION) -s -w" main.go

build-containerized: clean vendor dist/gobgp
	mkdir -p dist
	docker run --rm \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
	-v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
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
