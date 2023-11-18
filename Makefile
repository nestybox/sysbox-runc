CONTAINER_ENGINE := docker
GO := go

# Obtain the current system architecture.
ifeq ($(SYS_ARCH),)
	UNAME_M := $(shell uname -m)
	ifeq ($(UNAME_M),x86_64)
		SYS_ARCH := amd64
	else ifeq ($(UNAME_M),aarch64)
		SYS_ARCH := arm64
	else ifeq ($(UNAME_M),arm)
		SYS_ARCH := armhf
	else ifeq ($(UNAME_M),armel)
		SYS_ARCH := armel
	endif
endif

# Set target architecture if not explicitly defined by user.
ifeq ($(TARGET_ARCH),)
	TARGET_ARCH := $(SYS_ARCH)
endif

RUNC_BUILDROOT := build
RUNC_BUILDDIR := $(RUNC_BUILDROOT)/$(TARGET_ARCH)
RUNC_TARGET := sysbox-runc
RUNC_DEBUG_TARGET := sysbox-runc-debug
RUNC_STATIC_TARGET := sysbox-runc-static

SOURCES := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/sbin
MANDIR := $(PREFIX)/share/man

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
RUNC_IMAGE := runc_dev$(if $(GIT_BRANCH_CLEAN),:$(GIT_BRANCH_CLEAN))

NBOX := /root/nestybox
RUNC := $(NBOX)/sysbox-runc

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_NO)-dirty,$(COMMIT_NO))
BUILT_AT := $(shell date)
BUILT_BY := $(shell git config user.name)

SYSIPC_DIR := ../sysbox-ipc
SYSIPC_SRC := $(shell find $(SYSIPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

SYSLIB_DIR := ../sysbox-libs
SYSLIB_SRC := $(shell find $(SYSLIB_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

SHIFTFS_MODULE_PRESENT = $(shell lsmod | grep shiftfs)

LDFLAGS := -X 'main.edition=${EDITION}' -X main.version=${VERSION} \
		-X main.commitId=$(COMMIT) -X 'main.builtAt=$(BUILT_AT)' \
		-X 'main.builtBy=$(BUILT_BY)'

KERNEL_REL := $(shell uname -r)
KERNEL_REL_MAJ := $(shell echo $(KERNEL_REL) | cut -d'.' -f1)
KERNEL_REL_MIN := $(shell echo $(KERNEL_REL) | cut -d'.' -f2)

# idmapped mount is supported in kernels >= 5.12
ifeq ($(shell test $(KERNEL_REL_MAJ) -gt 5; echo $$?),0)
	IDMAPPED_MNT := 1
endif

ifeq ($(shell test $(KERNEL_REL_MAJ) -eq 5; echo $$?),0)
	ifeq ($(shell test $(KERNEL_REL_MIN) -ge 12; echo $$?),0)
		IDMAPPED_MNT := 1
	endif
endif

ifeq ($(IDMAPPED_MNT),1)
	BUILDTAGS ?= seccomp apparmor idmapped_mnt
else
	BUILDTAGS ?= seccomp apparmor
endif

IMAGE_BASE_DISTRO := $(shell cat /etc/os-release | grep "^ID=" | cut -d "=" -f2 | tr -d '"')

# Identify kernel-headers path if not previously defined. Notice that this logic is already
# present in Sysbox's Makefile; we are duplicating it here to keep sysbox-runc as independent
# as possible. If KERNEL_HEADERS is not already defined, we will assume that the same applies
# to all related variables declared below.
ifeq ($(IMAGE_BASE_DISTRO),$(filter $(IMAGE_BASE_DISTRO),centos fedora redhat almalinux rocky amzn))
	IMAGE_BASE_RELEASE := $(shell cat /etc/os-release | grep "^VERSION_ID" | cut -d "=" -f2 | tr -d '"' | cut -d "." -f1)
	KERNEL_HEADERS := kernels/$(KERNEL_REL)
else
	IMAGE_BASE_RELEASE := $(shell cat /etc/os-release | grep "^VERSION_CODENAME" | cut -d "=" -f2)
	ifeq ($(IMAGE_BASE_DISTRO),linuxmint)
		IMAGE_BASE_DISTRO := ubuntu
		ifeq ($(IMAGE_BASE_RELEASE),$(filter $(IMAGE_BASE_RELEASE),ulyana ulyssa uma))
			IMAGE_BASE_RELEASE := focal
		endif
		ifeq ($(IMAGE_BASE_RELEASE),$(filter $(IMAGE_BASE_RELEASE),tara tessa tina tricia))
			IMAGE_BASE_RELEASE := bionic
		endif
	endif
	KERNEL_HEADERS := linux-headers-$(KERNEL_REL)
	KERNEL_HEADERS_BASE := $(shell find /usr/src/$(KERNEL_HEADERS) -maxdepth 1 -type l -exec readlink {} \; | cut -d"/" -f2 | egrep -v "^\.\." | head -1)
endif

ifeq ($(KERNEL_HEADERS_BASE), )
	KERNEL_HEADERS_MOUNTS := -v /usr/src/$(KERNEL_HEADERS):/usr/src/$(KERNEL_HEADERS):ro
else
	KERNEL_HEADERS_MOUNTS := -v /usr/src/$(KERNEL_HEADERS):/usr/src/$(KERNEL_HEADERS):ro \
				 -v /usr/src/$(KERNEL_HEADERS_BASE):/usr/src/$(KERNEL_HEADERS_BASE):ro
endif

ifeq ($(shell $(GO) env GOOS),linux)
	ifeq (,$(filter $(shell $(GO) env GOARCH),mips mipsle mips64 mips64le ppc64))
		GO_BUILDMODE := "-buildmode=pie"
	endif
endif

# Set cross-compilation flags if applicable.
ifneq ($(SYS_ARCH),$(TARGET_ARCH))
	ifeq ($(TARGET_ARCH),armel)
		GO_XCOMPILE := CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 CC=arm-linux-gnueabi-gcc
	else ifeq ($(TARGET_ARCH),armhf)
		GO_XCOMPILE := CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc
	else ifeq ($(TARGET_ARCH),arm64)
		GO_XCOMPILE = CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc
	else ifeq ($(TARGET_ARCH),amd64)
		GO_XCOMPILE = CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-gnu-gcc
	endif
endif

GO_BUILD := $(GO_XCOMPILE) $(GO) build $(GO_BUILDMODE) -buildvcs=false -trimpath $(EXTRA_FLAGS) \
		-tags "$(BUILDTAGS)" -ldflags "${LDFLAGS}"

GO_BUILD_STATIC := CGO_ENABLED=1 $(GO_XCOMPILE) $(GO) build -buildvcs=false -trimpath $(EXTRA_FLAGS) \
		-tags "$(BUILDTAGS) netgo osusergo" -ldflags "-extldflags -static ${LDFLAGS}"

GO_BUILD_DEBUG := $(GO_XCOMPILE) $(GO) build -buildvcs=false --buildmode=exe -trimpath $(EXTRA_FLAGS) \
		-tags "$(BUILDTAGS)" -gcflags="all=-N -l" -ldflags "${LDFLAGS}"

RUN_TEST_CONT := $(CONTAINER_ENGINE) run ${DOCKER_RUN_PROXY} \
		-t --privileged --rm                         \
		-e SYS_ARCH=$(SYS_ARCH)                      \
		-e TARGET_ARCH=$(TARGET_ARCH)                \
		-v $(CURDIR):$(RUNC)                         \
		-v $(CURDIR)/../sysbox-ipc:$(NBOX)/sysbox-ipc        \
		-v $(CURDIR)/../sysbox-libs:$(NBOX)/sysbox-libs      \
		-v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro \
		-v $(GOPATH)/pkg/mod:/go/pkg/mod                            \
		$(KERNEL_HEADERS_MOUNTS)                                    \
		$(RUNC_IMAGE)

.DEFAULT: sysbox-runc

sysbox-runc: $(RUNC_BUILDDIR)/$(RUNC_TARGET)

$(RUNC_BUILDDIR)/$(RUNC_TARGET): $(SOURCES) $(SYSIPC_SRC) $(SYSLIB_SRC)
	$(GO_BUILD) -o $(RUNC_BUILDDIR)/$(RUNC_TARGET) .

sysbox-runc-debug: $(RUNC_BUILDDIR)/$(RUNC_DEBUG_TARGET)

# -buildmode=exe required in order to debug nsenter (cgo)
$(RUNC_BUILDDIR)/$(RUNC_DEBUG_TARGET):
	$(GO_BUILD_DEBUG) -o $(RUNC_BUILDDIR)/$(RUNC_TARGET) .

all: $(RUNC_BUILDDIR)/$(RUNC_TARGET) recvtty

recvtty:
	$(GO_BUILD) -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

static: $(SOURCES) $(SYSIPC_SRC) $(SYSLIB_SRC)
	$(GO_BUILD_STATIC) -o $(RUNC_BUILDDIR)/$(RUNC_TARGET) .
	$(GO_BUILD_STATIC) -o contrib/cmd/recvtty/recvtty ./contrib/cmd/recvtty

release:
	script/release.sh -r release/$(VERSION) -v $(VERSION)

dbuild: runcimage
	$(RUN_TEST_CONT) make clean all

gomod-tidy:
	$(GO) mod tidy

lint:
	$(GO) vet ./...
	$(GO) fmt ./...

man:
	man/md2man-all.sh

runcimage:
	$(CONTAINER_ENGINE) build $(CONTAINER_ENGINE_BUILD_FLAGS) -t $(RUNC_IMAGE) .

# Note: sysbox-runc does not support rootless mode, so rootless integration tests are not invoked as part of test or localtest
test:
	make unittest integration integration-shiftuid

localtest:
	make localunittest localintegration localintegration-shiftuid

unittest: runcimage
	$(RUN_TEST_CONT) make localunittest TESTFLAGS=${TESTFLAGS}

localunittest: all
	$(GO) test -timeout 3m -tags "$(BUILDTAGS)" $(TESTFLAGS) -v ./...

integration: runcimage
	$(RUN_TEST_CONT) make localintegration TESTPATH=${TESTPATH}

integration-shiftuid: runcimage
ifeq ($(SHIFTFS_MODULE_PRESENT),)
	@printf "\n** Skipped 'integration-shiftuid' target due to missing 'shiftfs' module **\n\n"
else
	$(RUN_TEST_CONT) make localintegration-shiftuid TESTPATH=${TESTPATH}
endif

localintegration: all
	bats -t tests/integration$(TESTPATH)

localintegration-shiftuid: all
ifeq ($(SHIFTFS_MODULE_PRESENT),)
	@printf "\n** Skipped 'localintegration-shiftuid' target due to missing 'shiftfs' module **\n\n"
else
	SHIFT_ROOTFS_UIDS=true bats -t tests/integration${TESTPATH}
endif

shell: runcimage
	$(CONTAINER_ENGINE) run ${DOCKER_RUN_PROXY} \
		-it --privileged --rm               \
		-e SYS_ARCH=$(SYS_ARCH)             \
		-e TARGET_ARCH=$(TARGET_ARCH)       \
		-v $(CURDIR):$(RUNC)                                 \
		-v $(CURDIR)/../sysbox-ipc:$(NBOX)/sysbox-ipc        \
		-v $(CURDIR)/../sysbox-libs:$(NBOX)/sysbox-libs      \
		-v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro \
		-v $(GOPATH)/pkg/mod:/go/pkg/mod                            \
		$(KERNEL_HEADERS_MOUNTS)                                    \
		$(RUNC_IMAGE) bash

install:
	install -D -m0755 $(RUNC_BUILDDIR)/$(RUNC_TARGET) $(BINDIR)/$(RUNC_TARGET)

install-bash:
	install -D -m0644 contrib/completions/bash/$(RUNC_TARGET) $(PREFIX)/share/bash-completion/completions/$(RUNC_TARGET)

install-man: man
	install -d -m 755 $(MANDIR)/man8
	install -D -m 644 man/man8/*.8 $(MANDIR)/man8

uninstall:
	rm -f $(BINDIR)/$(RUNC_TARGET)

uninstall-bash:
	rm -f $(PREFIX)/share/bash-completion/completions/$(RUNC_TARGET)

clean:
	rm -rf $(RUNC_BUILDDIR)/$(RUNC_TARGET)
	rm -f contrib/cmd/recvtty/recvtty
	rm -rf release
	rm -rf man/man8

distclean: clean
	rm -rf $(SYSFS_BUILDROOT)

validate:
	script/validate-gofmt
	script/validate-c
	$(GO) vet ./...

shellcheck:
	shellcheck tests/integration/*.bats
	# TODO: add shellcheck for sh files

shfmt:
	shfmt -ln bats -d -w tests/integration/*.bats
	shfmt -ln bash -d -w man/*.sh script/* tests/*.sh tests/integration/*.bash

ci: validate test release

# memoize allpackages, so that it's executed only once and only if used
_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)

listpackages:
	@echo $(allpackages)

.PHONY: runc all recvtty static release dbuild lint man runcimage \
	test localtest unittest localunittest integration localintegration \
	rootlessintegration localrootlessintegration shell install install-bash \
	install-man uninstall uninstall-bash clean validate ci shfmt shellcheck
