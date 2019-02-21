// +build linux

package libsyscontainer

import (
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// sysboxfsMounts is a list of system container mounts backed by sysbox-fs;
// please keep in alphabetical order.
var sysboxfsMounts = []specs.Mount{
	specs.Mount{
		Destination: "/proc",
		Source:      "proc",
		Type:        "proc",
		Options:     []string{"nosuid", "noexec", "nodev"},
	},
	// specs.Mount{
	// 	Destination: "/proc/cpuinfo",
	// 	Source:      "/var/lib/sysboxfs/proc/cpuinfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate"
	// },
	// specs.Mount{
	// 	Destination: "/proc/cgroups",
	// 	Source:      "/var/lib/sysboxfs/proc/cgroups",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/devices",
	// 	Source:      "/var/lib/sysboxfs/proc/devices",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/diskstats",
	// 	Source:      "/var/lib/sysboxfs/proc/diskstats",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/loadavg",
	// 	Source:      "/var/lib/sysboxfs/proc/loadavg",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/meminfo",
	// 	Source:      "/var/lib/sysboxfs/proc/meminfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/pagetypeinfo",
	// 	Source:      "/var/lib/sysboxfs/proc/pagetypeinfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/partitions",
	// 	Source:      "/var/lib/sysboxfs/proc/partitions",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/stat",
	// 	Source:      "/var/lib/sysboxfs/proc/stat",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/swaps",
	// 	Source:      "/var/lib/sysboxfs/proc/swaps",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/sys",
	// 	Source:      "/var/lib/sysboxfs/proc/sys",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	specs.Mount{
		Destination: "/proc/uptime",
		Source:      "/var/lib/sysboxfs/proc/uptime",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
}

var linuxCaps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FSETID",
	"CAP_FOWNER",
	"CAP_MKNOD",
	"CAP_NET_RAW",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETFCAP",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_SYS_CHROOT",
	"CAP_KILL",
	"CAP_AUDIT_WRITE",
	"CAP_DAC_READ_SEARCH",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_LEASE",
	"CAP_AUDIT_CONTROL",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
}

// idRangeMin represents the minimum uid/gid range required by a sys container instance
var idRangeMin uint32 = 65536

// cfgNamespaces checks that the namespace config is valid and adds any missing Linux
// namespaces to the system container config
func cfgNamespaces(spec *specs.Spec) error {

	reqNs := []specs.LinuxNamespaceType{"user", "pid", "ipc", "uts", "mount", "network"}

	// Ensure that the config has all the required namespaces
	for _, ns := range reqNs {
		found := false
		for _, cfgNs := range spec.Linux.Namespaces {
			if cfgNs.Type == ns {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("container spec missing the %s namespace", ns)
		}
	}

	// Add any missing namespaces (currently the cgroup namespace only)
	found := false
	for _, cfgNs := range spec.Linux.Namespaces {
		if cfgNs.Type == "cgroup" {
			found = true
		}
	}

	if !found {
		newns := specs.LinuxNamespace{
			Type: "cgroup",
			Path: "",
		}
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, newns)
	}

	return nil
}

// cfgIDMappings checks that the uid and gid configs are valid
func cfgIDMappings(spec *specs.Spec) error {

	if len(spec.Linux.UIDMappings) == 0 {
		return fmt.Errorf("container spec missing uid mappings")
	}

	if len(spec.Linux.GIDMappings) == 0 {
		return fmt.Errorf("container spec missing gid mappings")
	}

	// Verify the mapping is valid. Note that we don't disallow mappings that map to the host
	// root UID (i.e., we honor the ID config). Some runc tests use such mappings.

	validMapFound := false
	for _, mapping := range spec.Linux.UIDMappings {
		if mapping.ContainerID == 0 && mapping.Size >= idRangeMin {
			validMapFound = true
		}
	}
	if !validMapFound {
		return fmt.Errorf("container spec uid mapping does not map %d uids starting at container uid 0", idRangeMin)
	}

	validMapFound = false
	for _, mapping := range spec.Linux.GIDMappings {
		if mapping.ContainerID == 0 && mapping.Size >= idRangeMin {
			validMapFound = true
		}
	}
	if !validMapFound {
		return fmt.Errorf("container spec gid mapping does not map %d gids starting at container gid 0", idRangeMin)
	}

	return nil
}

// cfgCapabilities sets the capabilities for the root process in the system container
func cfgCapabilities(spec *specs.Spec) {

	// In a system container, root has all capabilities within the container's user
	// namespace; note however that the kernel will only allow privileged access to
	// namespaced resources and restrict access to non-namespaced resources.
	caps := spec.Process.Capabilities

	caps.Bounding = linuxCaps
	caps.Effective = linuxCaps
	caps.Inheritable = linuxCaps
	caps.Permitted = linuxCaps
	caps.Ambient = linuxCaps
}

// cfgMaskedPaths removes from the container's config any masked paths for which
// sysbox-fs will handle accesses.
func cfgMaskedPaths(spec *specs.Spec) {
	paths := spec.Linux.MaskedPaths
	for i := 0; i < len(paths); i++ {
		for _, mount := range sysboxfsMounts {
			if paths[i] == mount.Destination {
				paths = append(paths[:i], paths[i+1:]...)
				i--
				break
			}
		}
	}
	spec.Linux.MaskedPaths = paths
}

// cfgReadonlyPaths removes from the container's config any read-only paths for which
// sysbox-fs will handle accesses.
func cfgReadonlyPaths(spec *specs.Spec) {
	paths := spec.Linux.ReadonlyPaths
	for i := 0; i < len(paths); i++ {
		for _, mount := range sysboxfsMounts {
			if paths[i] == mount.Destination {
				paths = append(paths[:i], paths[i+1:]...)
				i--
				break
			}
		}
	}
	spec.Linux.ReadonlyPaths = paths
}

// cfgSysboxfsMounts adds the sysbox-fs mounts to the containers config.
func cfgSysboxfsMounts(spec *specs.Spec) {

	// remove from the config any mounts that conflict with sysboxfs mounts
	for i := 0; i < len(spec.Mounts); i++ {
		for _, mount := range sysboxfsMounts {
			if spec.Mounts[i].Destination == mount.Destination {
				spec.Mounts = append(spec.Mounts[:i], spec.Mounts[i+1:]...)
				i--
				break
			}
		}
	}

	// add sysboxfs mounts to the config
	for _, mount := range sysboxfsMounts {
		spec.Mounts = append(spec.Mounts, mount)
	}
}

// cfgCgroupPath configures the system container's cgroupPath.
func cfgCgroupPath(spec *specs.Spec) error {

	// System container specs require a cgroupsPath
	if spec.Linux.CgroupsPath == "" {
		return fmt.Errorf("cgroupsPath not found in spec")
	}

	// Remove the read-only attribute from the cgroup mount; this is fine because the sys
	// container's cgroup root will be in a child cgroup of the cgroup that controls the
	// sys container's resources; thus, root processes inside the sys container will be
	// able to allocate cgroup resources yet not modify the resources allocated to the sys
	// container itself.
	for i, mount := range spec.Mounts {
		if mount.Type == "cgroup" {
			for j := 0; j < len(mount.Options); j++ {
				if mount.Options[j] == "ro" {
					mount.Options = append(mount.Options[:j], mount.Options[j+1:]...)
					j--
				}
			}
			spec.Mounts[i].Options = mount.Options
		}
	}

	return nil
}

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(spec *specs.Spec, strict bool) error {

	// TODO: Modify the spec for sys containers here;
	// validate and return the modified spec. Also, modify the seccomp
	// config for sys containers. Log messages when performing conversions.
	// If comparison should be strict, report errors on incompatible configs.

	if err := cfgNamespaces(spec); err != nil {
		return fmt.Errorf("invalid namespace config: %v", err)
	}

	if err := cfgIDMappings(spec); err != nil {
		return fmt.Errorf("invalid user/group ID config: %v", err)
	}

	cfgCapabilities(spec)
	cfgMaskedPaths(spec)
	cfgReadonlyPaths(spec)
	cfgSysboxfsMounts(spec)

	if err := cfgCgroupPath(spec); err != nil {
		return fmt.Errorf("failed to configure cgroup mounts: %v", err)
	}

	// Verify rootfs has uid/gid ownership matching the uid/gid config

	// Remove readonly root filesystem config (spec.Root.Readonly)

	// Remove prestart hooks

	// cfg process spec
	// - uid/gid must be 0
	// - entry point must be system daemon

	// cfg seccomp config

	return nil
}
