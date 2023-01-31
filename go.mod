module github.com/nestybox/sysbox-runc

go 1.14

require (
	github.com/Masterminds/semver v1.5.0
	github.com/checkpoint-restore/go-criu/v4 v4.1.0
	github.com/cilium/ebpf v0.3.0
	github.com/containerd/console v1.0.1
	github.com/coreos/go-systemd/v22 v22.1.0
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/go-units v0.4.0
	github.com/godbus/dbus/v5 v5.0.3
	github.com/golang/protobuf v1.4.3
	github.com/moby/sys/mountinfo v0.4.0
	github.com/mrunalp/fileutils v0.5.0
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/capability v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/dockerUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/idShiftUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/libseccomp-golang v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/utils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/mount v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/overlayUtils v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runc v1.0.0-rc9.0.20210126000000-2be806d1391d
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/opencontainers/selinux v1.8.0
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.5.0
	github.com/sirupsen/logrus v1.7.0
	// NOTE: urfave/cli must be <= v1.22.1 due to a regression: https://github.com/urfave/cli/issues/1092
	github.com/urfave/cli v1.22.1
	github.com/vishvananda/netlink v1.1.0
	github.com/willf/bitset v1.1.11
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
)

replace github.com/nestybox/sysbox-ipc => ../sysbox-ipc

replace github.com/nestybox/sysbox-libs/libseccomp-golang => ../sysbox-libs/libseccomp-golang

replace github.com/nestybox/sysbox-libs/formatter => ../sysbox-libs/formatter

replace github.com/nestybox/sysbox-libs/capability => ../sysbox-libs/capability

replace github.com/nestybox/sysbox-libs/utils => ../sysbox-libs/utils

replace github.com/nestybox/sysbox-libs/dockerUtils => ../sysbox-libs/dockerUtils

replace github.com/nestybox/sysbox-libs/idShiftUtils => ../sysbox-libs/idShiftUtils

replace github.com/nestybox/sysbox-libs/overlayUtils => ../sysbox-libs/overlayUtils

replace github.com/nestybox/sysbox-libs/mount => ../sysbox-libs/mount

replace github.com/opencontainers/runc => ./
