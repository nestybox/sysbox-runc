.PHONY: all shell dbuild man release \
	    localtest localunittest localintegration \
	    test unittest integration \
	    cross localcross recvtty

GO := go

RUNC_TARGET := sysbox-runc
RUNC_DEBUG_TARGET := sysbox-runc-debug

SOURCES := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')
PREFIX := $(DESTDIR)/usr/local
BINDIR := $(PREFIX)/sbin
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
RUNC_IMAGE := runc_dev$(if $(GIT_BRANCH_CLEAN),:$(GIT_BRANCH_CLEAN))
NBOX := /root/nestybox
RUNC := $(NBOX)/sysbox-runc
BUILDTAGS ?= seccomp
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no),"${COMMIT_NO}-dirty","${COMMIT_NO}")

SYSIPC := github.com/nestybox/sysbox/sysbox-ipc
SYSIPC_DIR := ../sysbox-ipc
SYSIPC_SRC := $(shell find $(SYSIPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

LIBSECCOMP_DIR := ../sysbox-libs/libseccomp-golang
LIBSECCOMP_SRC := $(shell find $(LIBSECCOMP_DIR) 2>&1 | grep -E '.*\.(go)')

MAN_DIR := $(CURDIR)/man/man8
MAN_PAGES = $(shell ls $(MAN_DIR)/*.8)
MAN_PAGES_BASE = $(notdir $(MAN_PAGES))
MAN_INSTALL_PATH := ${PREFIX}/share/man/man8/

RELEASE_DIR := $(CURDIR)/release

SHELL := $(shell command -v bash 2>/dev/null)

SHIFTFS_MODULE_PRESENT = $(shell lsmod | grep shiftfs)

LDFLAGS := '-X main.version=${VERSION} -X main.commitId=${COMMIT_ID} \
			-X "main.builtAt=${BUILT_AT}" -X main.builtBy=${BUILT_BY}'

# Identify kernel-headers path if not previously defined. Notice that this logic is already
# present in Sysbox's Makefile; we are duplicating it here to keep sysbox-runc as independent
# as possible. If KERNEL_HEADERS is not already defined, we will assume that the same applies
# to all related variables declared below.
ifeq ($(KERNEL_HEADERS),)
	KERNEL_REL := $(shell uname -r)
	IMAGE_BASE_DISTRO := $(shell lsb_release -is | tr '[:upper:]' '[:lower:]')
	ifeq ($(IMAGE_BASE_DISTRO),$(filter $(IMAGE_BASE_DISTRO),centos fedora redhat))
		KERNEL_HEADERS := kernels/$(KERNEL_REL)
		KERNEL_HEADERS_MOUNTS := -v /usr/src/$(KERNEL_HEADERS):/usr/src/$(KERNEL_HEADERS):ro
	else
		KERNEL_HEADERS := linux-headers-$(KERNEL_REL)
		KERNEL_HEADERS_BASE := $(shell find /usr/src/$(KERNEL_HEADERS) -maxdepth 1 -type l -exec readlink {} \; | cut -d"/" -f2 | egrep -v "^\.\." | head -1)
		KERNEL_HEADERS_MOUNTS := -v /usr/src/$(KERNEL_HEADERS):/usr/src/$(KERNEL_HEADERS):ro \
					 -v /usr/src/$(KERNEL_HEADERS_BASE):/usr/src/$(KERNEL_HEADERS_BASE):ro
	endif
endif

RUN_TEST_CONT := docker run ${DOCKER_RUN_PROXY} -t --privileged --rm \
		-v $(CURDIR):$(RUNC)                                 \
		-v $(CURDIR)/../sysbox-ipc:$(NBOX)/sysbox-ipc        \
		-v $(CURDIR)/../sysbox-libs:$(NBOX)/sysbox-libs      \
		-v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro \
		-v $(GOPATH)/pkg/mod:/go/pkg/mod                            \
		$(KERNEL_HEADERS_MOUNTS)                                    \
		$(RUNC_IMAGE)

.DEFAULT: $(RUNC_TARGET)

$(RUNC_TARGET): $(SOURCES) $(SYSIPC_SRC) $(LIBSECCOMP_SRC) contrib/cmd/recvtty/recvtty
	$(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags ${LDFLAGS} -tags "$(BUILDTAGS)" \
		-o $(RUNC_TARGET) .

# -buildmode=exe required in order to debug nsenter (cgo)
$(RUNC_DEBUG_TARGET): $(SOURCES) $(SYSIPC_SRC) contrib/cmd/recvtty/recvtty
	$(GO) build -buildmode=exe $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -tags "$(BUILDTAGS)" -gcflags="all=-N -l" -o $(RUNC_TARGET) .

all: $(RUNC_TARGET) recvtty

recvtty: contrib/cmd/recvtty/recvtty

contrib/cmd/recvtty/recvtty: $(SOURCES)
	$(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -tags "$(BUILDTAGS)" -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

static: $(SOURCES) $(SYSIPC_SRC)
	CGO_ENABLED=1 $(GO) build $(EXTRA_FLAGS) -tags "$(BUILDTAGS) netgo osusergo static_build" -installsuffix netgo -ldflags "-w -extldflags -static -X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -o $(RUNC_TARGET) .
	CGO_ENABLED=1 $(GO) build $(EXTRA_FLAGS) -tags "$(BUILDTAGS) netgo osusergo static_build" -installsuffix netgo -ldflags "-w -extldflags -static -X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

release:
	script/release.sh -r release/$(VERSION) -v $(VERSION)

dbuild: runcimage
	docker run ${DOCKER_RUN_PROXY} --rm -v $(CURDIR):$(RUNC) --privileged $(RUNC_IMAGE) make clean all

lint:
	$(GO) vet $(allpackages)
	$(GO) fmt $(allpackages)

man:
	man/md2man-all.sh

runcimage:
	docker build ${DOCKER_BUILD_PROXY} -t $(RUNC_IMAGE) .

# Note: sysbox-runc does not support rootless mode, so rootless integration tests are not invoked as part of test or localtest
test:
	make unittest integration integration-shiftuid

localtest:
	make localunittest localintegration localintegration-shiftuid

unittest: runcimage
	$(RUN_TEST_CONT) make localunittest TESTFLAGS=${TESTFLAGS}

localunittest: all
	$(GO) test -timeout 3m -tags "$(BUILDTAGS)" ${TESTFLAGS} -v $(allpackages)

integration: runcimage
	$(RUN_TEST_CONT) make localintegration TESTPATH=${TESTPATH}

integration-shiftuid: runcimage
ifeq ($(SHIFTFS_MODULE_PRESENT),)
	@printf "\n** Skipped 'integration-shiftuid' target due to missing 'shiftfs' module **\n\n"
else
	$(RUN_TEST_CONT) make localintegration-shiftuid TESTPATH=${TESTPATH}
endif

localintegration: all
	bats -t tests/integration${TESTPATH}

localintegration-shiftuid: all
ifeq ($(SHIFTFS_MODULE_PRESENT),)
	@printf "\n** Skipped 'localintegration-shiftuid' target due to missing 'shiftfs' module **\n\n"
else
	SHIFT_UIDS=true bats -t tests/integration${TESTPATH}
endif

rootlessintegration: runcimage
	$(RUN_TEST_CONT) make localrootlessintegration

localrootlessintegration: all
	tests/rootless.sh

shell: runcimage
	docker run ${DOCKER_RUN_PROXY} -ti --privileged --rm \
	   -v $(CURDIR):$(RUNC)                              \
	   -v $(CURDIR)/../sysbox-ipc:$(NBOX)/sysbox-ipc     \
	   -v $(CURDIR)/../lib:$(NBOX)/lib                   \
	   -v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro \
	   -v $(GOPATH)/pkg/mod:/go/pkg/mod                            \
	   $(KERNEL_HEADERS_MOUNTS)                                    \
	   $(RUNC_IMAGE) bash

install:
	install -D -m0755 $(RUNC_TARGET) $(BINDIR)/$(RUNC_TARGET)

install-bash:
	install -D -m0644 contrib/completions/bash/$(RUNC_TARGET) $(PREFIX)/share/bash-completion/completions/$(RUNC_TARGET)

install-man:
	install -d -m 755 $(MAN_INSTALL_PATH)
	install -m 644 $(MAN_PAGES) $(MAN_INSTALL_PATH)

uninstall:
	rm -f $(BINDIR)/$(RUNC_TARGET)

uninstall-bash:
	rm -f $(PREFIX)/share/bash-completion/completions/$(RUNC_TARGET)

uninstall-man:
	rm -f $(addprefix $(MAN_INSTALL_PATH),$(MAN_PAGES_BASE))

clean:
	rm -f $(RUNC_TARGET) $(RUNC_TARGET)-*
	rm -f contrib/cmd/recvtty/recvtty
	rm -rf $(RELEASE_DIR)
	rm -rf $(MAN_DIR)

validate:
	script/validate-gofmt
	script/validate-c
	$(GO) vet $(allpackages)

ci: validate test release

listpackages:
	@echo $(allpackages)

cross: runcimage
	docker run ${DOCKER_RUN_PROXY} -e BUILDTAGS="$(BUILDTAGS)" --rm -v $(CURDIR):$(RUNC) $(RUNC_IMAGE) make localcross

localcross:
	CGO_ENABLED=1 GOARCH=arm GOARM=6 CC=arm-linux-gnueabi-gcc $(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -tags "$(BUILDTAGS)" -o runc-armel .
	CGO_ENABLED=1 GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc $(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -tags "$(BUILDTAGS)" -o runc-armhf .
	CGO_ENABLED=1 GOARCH=arm64 CC=aarch64-linux-gnu-gcc $(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -tags "$(BUILDTAGS)" -o runc-arm64 .
	CGO_ENABLED=1 GOARCH=ppc64le CC=powerpc64le-linux-gnu-gcc $(GO) build -buildmode=pie $(EXTRA_FLAGS) -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION} $(EXTRA_LDFLAGS)" -tags "$(BUILDTAGS)" -o runc-ppc64le .

# memoize allpackages, so that it's executed only once and only if used
_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)
