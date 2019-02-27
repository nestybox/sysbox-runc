package syscontSpec

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Example returns an example OCI spec file for a system container
func Example(uid, gid, idRange uint32, bundle string) (*specs.Spec, error) {

	return &specs.Spec{
		Version: specs.Version,
		Root: &specs.Root{
			Path:     "rootfs",
		},
		Hostname: "syscont",
		Process: &specs.Process{
			Terminal: true,
			User:     specs.User{},
			Args: []string{
				"sh",
			},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
			},
			Cwd: "/",
			NoNewPrivileges: true,
			Capabilities: &specs.LinuxCapabilities{
				Bounding: linuxCaps,
				Permitted: linuxCaps,
				Inheritable: linuxCaps,
				Ambient: linuxCaps,
				Effective: linuxCaps,
			},
			Rlimits: []specs.POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: uint64(1024),
					Soft: uint64(1024),
				},
			},
		},
		Mounts: []specs.Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
				Options:     nil,
			},
			{
				Destination: "/dev",
				Type:        "tmpfs",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
			},
			{
				Destination: "/dev/pts",
				Type:        "devpts",
				Source:      "devpts",
				Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"},  // TODO: skip "gid=5" option until we come up with a valid uid/gid allocation strategy
			},
			{
				Destination: "/dev/shm",
				Type:        "tmpfs",
				Source:      "shm",
				Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
			},
			{
				Destination: "/dev/mqueue",
				Type:        "mqueue",
				Source:      "mqueue",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
			{
				Destination: "/sys",
				Type:        "sysfs",
				Source:      "sysfs",
				Options:     []string{"nosuid", "noexec", "nodev", "ro"},
			},
			{
				Destination: "/sys/fs/cgroup",
				Type:        "cgroup",
				Source:      "cgroup",
				Options:     []string{"nosuid", "noexec", "nodev", "relatime"},
			},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{
					Type: "user",
				},
				{
					Type: "pid",
				},
				{
					Type: "network",
				},
				{
					Type: "ipc",
				},
				{
					Type: "uts",
				},
				{
					Type: "mount",
				},
				{
					Type: "cgroup",
				},
			},
			UIDMappings: []specs.LinuxIDMapping{{
				HostID:      uid,
				ContainerID: 0,
				Size:        idRange,
			}},
			GIDMappings: []specs.LinuxIDMapping{{
				HostID:      gid,
				ContainerID: 0,
				Size:        idRange,
			}},
			MaskedPaths: []string{
				"/proc/kcore",
				"/proc/latency_stats",
				"/proc/timer_list",
				"/proc/timer_stats",
				"/proc/sched_debug",
				"/sys/firmware",
				"/proc/scsi",
			},
			ReadonlyPaths: []string{
				"/proc/asound",
				"/proc/bus",
				"/proc/fs",
				"/proc/irq",
				"/proc/sys",
				"/proc/sysrq-trigger",
			},
			CgroupsPath: "",
		},
	}, nil
}