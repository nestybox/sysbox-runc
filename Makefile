CONTAINER_ENGINE := docker
GO := go

RUNC_TARGET := sysbox-runc
RUNC_DEBUG_TARGET := sysbox-runc-debug

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/sbin
MANDIR := $(PREFIX)/share/man

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
RUNC_IMAGE := runc_dev$(if $(GIT_BRANCH_CLEAN),:$(GIT_BRANCH_CLEAN))
PROJECT := nestybox/sysbox-runc
BUILDTAGS ?= seccomp selinux apparmor
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
VERSION := $(shell cat ./VERSION)

ifeq ($(shell $(GO) env GOOS),linux)
	ifeq (,$(filter $(shell $(GO) env GOARCH),mips mipsle mips64 mips64le ppc64))
		GO_BUILDMODE := "-buildmode=pie"
	endif
endif
GO_BUILD := $(GO) build $(MOD_VENDOR) $(GO_BUILDMODE) $(EXTRA_FLAGS) -tags "$(BUILDTAGS)" \
	-ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"
GO_BUILD_STATIC := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) $(EXTRA_FLAGS) -tags "$(BUILDTAGS) netgo osusergo" \
	-ldflags "-w -extldflags -static -X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)"
GO_BUILD_DEBUG := $(GO) build $(MOD_VENDOR) --buildmode=exe $(EXTRA_FLAGS) -tags "$(BUILDTAGS)" \
	-ldflags "-X main.gitCommit=$(COMMIT) -X main.version=$(VERSION) $(EXTRA_LDFLAGS)" -gcflags="all=-N -l"

.DEFAULT: $(RUNC_TARGET)

$(RUNC_TARGET):
	$(GO_BUILD) -o $(RUNC_TARGET) .

# -buildmode=exe required in order to debug nsenter (cgo)
$(RUNC_DEBUG_TARGET):
	$(GO_BUILD_DEBUG) -o $(RUNC_TARGET) .

all: $(RUNC_TARGET) recvtty

recvtty:
	$(GO_BUILD) -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

static:
	$(GO_BUILD_STATIC) -o $(RUNC_TARGET) .
	$(GO_BUILD_STATIC) -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

release:
	script/release.sh -r release/$(VERSION) -v $(VERSION)

dbuild: runcimage
	$(CONTAINER_ENGINE) run $(CONTAINER_ENGINE_RUN_FLAGS) \
		--privileged --rm \
		-v $(CURDIR)/../sysbox-ipc:/go/src/nestybox/sysbox-ipc \
		-v $(CURDIR):/go/src/$(PROJECT) \
		$(RUNC_IMAGE) make clean all

lint:
	$(GO) vet ./...
	$(GO) fmt ./...

man:
	man/md2man-all.sh

runcimage:
	$(CONTAINER_ENGINE) build $(CONTAINER_ENGINE_BUILD_FLAGS) -t $(RUNC_IMAGE) .

# Note: sysbox-runc does not support rootless mode, so rootless integration tests are not invoked as part of test or localtest
test:
	make unittest integration

localtest:
	make localunittest localintegration

unittest: runcimage
	$(CONTAINER_ENGINE) run $(CONTAINER_ENGINE_RUN_FLAGS) \
		-t --privileged --rm \
		-v /lib/modules:/lib/modules:ro \
		-v $(CURDIR)/../sysbox-ipc:/go/src/nestybox/sysbox-ipc \
		-v $(CURDIR):/go/src/$(PROJECT) \
		$(RUNC_IMAGE) make localunittest TESTFLAGS=$(TESTFLAGS)

localunittest: all
	$(GO) test -timeout 3m -tags "$(BUILDTAGS)" $(TESTFLAGS) -v ./...

integration: runcimage
	$(CONTAINER_ENGINE) run $(CONTAINER_ENGINE_RUN_FLAGS) \
		-t --privileged --rm \
		-v /lib/modules:/lib/modules:ro \
		-v $(CURDIR)/../sysbox-ipc:/go/src/nestybox/sysbox-ipc \
		-v $(CURDIR):/go/src/$(PROJECT) \
		$(RUNC_IMAGE) make localintegration TESTPATH=$(TESTPATH)

localintegration: all
	bats -t tests/integration$(TESTPATH)

rootlessintegration: runcimage
	$(CONTAINER_ENGINE) run $(CONTAINER_ENGINE_RUN_FLAGS) \
		-t --privileged --rm \
		-v $(CURDIR)/../sysbox-ipc:/go/src/nestybox/sysbox-ipc \
		-v $(CURDIR):/go/src/$(PROJECT) \
		-e ROOTLESS_TESTPATH \
		$(RUNC_IMAGE) make localrootlessintegration

localrootlessintegration: all
	tests/rootless.sh

shell: runcimage
	$(CONTAINER_ENGINE) run $(CONTAINER_ENGINE_RUN_FLAGS) \
		-ti --privileged --rm \
		-v /lib/modules:/lib/modules:ro \
		-v $(CURDIR)/../sysbox-ipc:/go/src/nestybox/sysbox-ipc \
		-v $(CURDIR):/go/src/$(PROJECT) \
		$(RUNC_IMAGE) bash

install:
	install -D -m0755 runc $(DESTDIR)$(BINDIR)/$(RUNC_TARGET)

install-bash:
	install -D -m0644 contrib/completions/bash/runc $(DESTDIR)$(PREFIX)/share/bash-completion/completions/runc

install-man: man
	install -d -m 755 $(DESTDIR)$(MANDIR)/man8
	install -D -m 644 man/man8/*.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f $(RUNC_TARGET) $(RUNC_TARGET)-*
	rm -f contrib/cmd/recvtty/recvtty
	rm -rf release
	rm -rf man/man8

validate:
	script/validate-gofmt
	script/validate-c
	$(GO) vet ./...
	shellcheck tests/integration/*.bats
	# TODO: add shellcheck for sh files
	shfmt -ln bats -d tests/integration/*.bats
	shfmt -ln bash -d man/*.sh script/*.sh tests/*.sh tests/integration/*.bash

ci: validate test release

vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

verify-dependencies: vendor
	@test -z "$$(git status --porcelain -- go.mod go.sum vendor/)" \
		|| (echo -e "git status:\n $$(git status -- go.mod go.sum vendor/)\nerror: vendor/, go.mod and/or go.sum not up to date. Run \"make vendor\" to update"; exit 1) \
		&& echo "all vendor files are up to date."

cross: runcimage
	$(CONTAINER_ENGINE) run $(CONTAINER_ENGINE_RUN_FLAGS) \
		-e BUILDTAGS="$(BUILDTAGS)" --rm \
		-v $(CURDIR):/go/src/$(PROJECT) \
		$(RUNC_IMAGE) make localcross

localcross:
	CGO_ENABLED=1 GOARCH=arm GOARM=6 CC=arm-linux-gnueabi-gcc   $(GO_BUILD) -o runc-armel .
	CGO_ENABLED=1 GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc $(GO_BUILD) -o runc-armhf .
	CGO_ENABLED=1 GOARCH=arm64 CC=aarch64-linux-gnu-gcc         $(GO_BUILD) -o runc-arm64 .
	CGO_ENABLED=1 GOARCH=ppc64le CC=powerpc64le-linux-gnu-gcc   $(GO_BUILD) -o runc-ppc64le .

# memoize allpackages, so that it's executed only once and only if used
_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)

listpackages:
	@echo $(allpackages)

.PHONY: runc all recvtty static release dbuild lint man runcimage \
	test localtest unittest localunittest integration localintegration \
	rootlessintegration localrootlessintegration shell install install-bash \
	install-man clean validate ci \
	vendor verify-dependencies cross localcross
