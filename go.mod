module github.com/nestybox/sysbox-runc

go 1.13

require (
	github.com/Masterminds/semver v1.5.0
	github.com/checkpoint-restore/go-criu v0.0.0-20191125063657-fcdcd07065c5
	github.com/cobaugh/osrelease v0.0.0-20181218015638-a93a0a55a249
	github.com/containerd/console v1.0.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/go-units v0.4.0
	github.com/godbus/dbus v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.4.1
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/nestybox/libseccomp-golang v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox/dockerUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox/lib/capability v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox/utils v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runc v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/opencontainers/selinux v1.2.2
	github.com/pkg/errors v0.8.1
	github.com/pkg/profile v1.4.0
	github.com/sirupsen/logrus v1.4.2
	github.com/urfave/cli v1.20.0
	github.com/vishvananda/netlink v1.0.0
	golang.org/x/sys v0.0.0-20200420163511-1957bb5e6d1f
)

replace github.com/nestybox/sysbox-ipc => ../sysbox-ipc

replace github.com/nestybox/libseccomp-golang => ../lib/seccomp-golang

replace github.com/nestybox/sysbox/lib/capability => ../lib/capability

replace github.com/nestybox/sysbox/utils => ../lib/utils

replace github.com/nestybox/sysbox/dockerUtils => ../lib/dockerUtils

replace github.com/opencontainers/runc => ./

replace github.com/godbus/dbus => github.com/godbus/dbus/v5 v5.0.3
