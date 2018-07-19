# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut test-install-cni
###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=$(patsubst Dockerfile.%,%,$(wildcard Dockerfile.*))

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
        BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
        BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
ARCH ?= $(BUILDARCH)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif
###############################################################################
GO_BUILD_VER ?= v0.16

CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
SRC_FILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*" -not -path "./gobgp/*")
GOBGPD_VERSION?=$(shell git describe --tags --dirty)
CONTAINER_NAME?=calico/gobgpd
PACKAGE_NAME?=github.com/projectcalico/calico-bgp-daemon
LOCAL_USER_ID?=$(shell id -u $$USER)
BIN=bin/$(ARCH)

clean:
	rm -rf vendor
	rm -rf gobgp
	rm -rf $(BIN)

###############################################################################
# Building the binary
###############################################################################
build: $(BIN)/calico-bgp-daemon
build-all: $(addprefix sub-build-,$(ARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

vendor: glide.lock
	mkdir -p $(HOME)/.glide
	# To build without Docker just run "glide install -strip-vendor"
	docker run --rm \
    -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
    -v $(HOME)/.glide:/home/user/.glide:rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
      glide install -strip-vendor'

# instead of 'go get', run `git clone` and then `dep ensure && go build` so the files are cached
gobgp:
	git clone -b v1.33 https://github.com/osrg/gobgp gobgp

gobgp/vendor: gobgp
	docker run --rm \
		-v $(CURDIR)/gobgp:/go/src/github.com/osrg/gobgp \
		-w /go/src/github.com/osrg/gobgp \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e ARCH=$(ARCH) \
		-e GOARCH=$(ARCH) \
		$(CALICO_BUILD) dep ensure

$(BIN)/gobgp: gobgp gobgp/vendor
	mkdir -p $(@D)
	docker run --rm \
		-v $(CURDIR)/gobgp:/go/src/github.com/osrg/gobgp \
		-v $(CURDIR)/$(BIN):/outbin \
		-w /go/src/github.com/osrg/gobgp \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e ARCH=$(ARCH) \
		-e GOARCH=$(ARCH) \
		$(CALICO_BUILD) go build -v -o /outbin/gobgp github.com/osrg/gobgp/gobgp

$(BIN)/calico-bgp-daemon: $(SRC_FILES) vendor $(BIN)/gobgp
	-mkdir -p $(@D)
	-mkdir -p .go-pkg-cache
	docker run --rm \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
	-e GOCACHE=/go-cache \
	-e GOARCH=$(ARCH) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			go build -v -o $(BIN)/calico-bgp-daemon \
            	-ldflags "-X main.VERSION=$(GOBGPD_VERSION) -s -w" main.go ipam.go k8s.go'

###############################################################################
# Building the image
###############################################################################
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

image: $(CONTAINER_NAME)
$(CONTAINER_NAME): build
	docker build -t $(CONTAINER_NAME):latest-$(ARCH) -f Dockerfile.$(ARCH) .

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## tag images of one arch
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd  /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --vendor -s gobgp ./...'

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRC_FILES)

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: static-checks

## Deploys images to registry
cd: image
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images push IMAGETAG=${BRANCH_NAME}
	$(MAKE) tag-images push IMAGETAG=$(shell git describe --tags --dirty --always --long)

###############################################################################
# Release
###############################################################################
release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)
	$(MAKE) $(CONTAINER_NAME)
	# Check that the version output appears on a line of its own (the -x option to grep).
	# Tests that the "git tag" makes it into the binary. Main point is to catch "-dirty" builds
	@echo "Checking if the tag made it into the binary"
	docker run --rm $(CONTAINER_NAME):latest-$(ARCH) -v | grep -x $(VERSION) || (echo "Reported version:" `docker run --rm $(CONTAINER_NAME):latest-$(ARCH) -v` "\nExpected version: $(VERSION)" && exit 1)

	$(MAKE) tag IMAGETAG=$(VERSION) ARCH=$(ARCH)
	$(MAKE) tag IMAGETAG=latest ARCH=$(ARCH)
	$(MAKE) push IMAGETAG=$(VERSION) ARCH=$(ARCH)
	$(MAKE) push IMAGETAG=latest ARCH=$(ARCH)

	@echo "Now create a release on Github and attach the $(BIN)/gobgpd and $(BIN)/gobgp binaries"
	@echo "git push origin $(VERSION)"
