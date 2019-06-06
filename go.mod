module github.com/nestybox/sysvisor-runc

go 1.13

require (
	github.com/checkpoint-restore/go-criu v0.0.0-20190109184317-bdb7599cd87b
	github.com/cobaugh/osrelease v0.0.0-20181218015638-a93a0a55a249
	github.com/containerd/console v0.0.0-20181022165439-0650fd9eeb50
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/go-units v0.4.0
	github.com/godbus/dbus v5.0.0+incompatible
	github.com/golang/protobuf v1.3.1
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/nestybox/sysvisor-ipc v0.0.0-20190603003818-483605a8fbcf
	github.com/opencontainers/runc v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runtime-spec v0.1.2-0.20190207185410-29686dbc5559
	github.com/opencontainers/selinux v1.2.2
	github.com/pkg/errors v0.8.1
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/urfave/cli v1.20.0
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	golang.org/x/sys v0.0.0-20190602015325-4c4f7f33c9ed
)

replace github.com/opencontainers/runc => ./
