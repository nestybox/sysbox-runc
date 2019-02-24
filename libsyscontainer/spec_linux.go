// +build linux

package libsyscontainer

import (
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// sysvisorfsMounts is a list of system container mounts backed by sysvisor-fs;
// please keep in alphabetical order.
var sysvisorfsMounts = []specs.Mount{
	specs.Mount{
		Destination: "/proc",
		Source:      "proc",
		Type:        "proc",
		Options:     []string{"nosuid", "noexec", "nodev"},
	},
	// specs.Mount{
	// 	Destination: "/proc/cpuinfo",
	// 	Source:      "/var/lib/sysvisorfs/proc/cpuinfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate"
	// },
	// specs.Mount{
	// 	Destination: "/proc/cgroups",
	// 	Source:      "/var/lib/sysvisorfs/proc/cgroups",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/devices",
	// 	Source:      "/var/lib/sysvisorfs/proc/devices",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/diskstats",
	// 	Source:      "/var/lib/sysvisorfs/proc/diskstats",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/loadavg",
	// 	Source:      "/var/lib/sysvisorfs/proc/loadavg",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/meminfo",
	// 	Source:      "/var/lib/sysvisorfs/proc/meminfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/pagetypeinfo",
	// 	Source:      "/var/lib/sysvisorfs/proc/pagetypeinfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/partitions",
	// 	Source:      "/var/lib/sysvisorfs/proc/partitions",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/stat",
	// 	Source:      "/var/lib/sysvisorfs/proc/stat",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/swaps",
	// 	Source:      "/var/lib/sysvisorfs/proc/swaps",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/sys",
	// 	Source:      "/var/lib/sysvisorfs/proc/sys",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	specs.Mount{
		Destination: "/proc/uptime",
		Source:      "/var/lib/sysvisorfs/proc/uptime",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
}

// cfgNamespaces adds any missing Linux namespace to the system container config
func cfgNamespaces(spec *specs.Spec) {
	nsTypes := []specs.LinuxNamespaceType{"user", "pid", "ipc", "uts", "mount", "network", "cgroup"}

	for _, nsType := range nsTypes {
		found := false
		for _, ns := range spec.Linux.Namespaces {
			if ns.Type == nsType {
				found = true
			}
		}
		if !found {
			newns := specs.LinuxNamespace{
				Type: nsType,
				Path: "",
			}
			spec.Linux.Namespaces = append(spec.Linux.Namespaces, newns)
		}
	}
}

// cfgUidMappings sets up uid mappings in the system container config
func cfgUidMappings(spec *specs.Spec) {

	// TODO: each sys container should get a unique uid range from sysvisor's subuid range
	// For now we just use the entire sysvisor's subuid range for all sys containers (this
	// is not secure as it does not isolate sys container users in case a process escapes
	// the sys container).

	// Remove any existing uid mappings
	spec.Linux.UIDMappings = spec.Linux.UIDMappings[:0]

	// Set the new uid mappings
	uidMap := specs.LinuxIDMapping{
		ContainerID: 0,  // root
		HostID: 231072,  // fixme
		Size: 65536,     // fixme
	}
	spec.Linux.UIDMappings = append(spec.Linux.UIDMappings, uidMap)
}

// cfgGidMappings sets up gid mappings in the system container config
func cfgGidMappings(spec *specs.Spec) {

	// TODO: each sys container should get a unique gid range from sysvisor's subgid range
	// For now we just use the entire sysvisor's subgid range for all sys containers (this
	// is not secure as it does not isolate sys container users in case a process escapes
	// the sys container).

	// Remove any existing gid mappings
	spec.Linux.GIDMappings = spec.Linux.GIDMappings[:0]

	// Set the new gid mappings
	gidMap := specs.LinuxIDMapping{
		ContainerID: 0,  // root
		HostID: 231072,  // fixme
		Size: 65536,     // fixme
	}
	spec.Linux.GIDMappings = append(spec.Linux.GIDMappings, gidMap)
}

// cfgCapabilities sets the capabilities for the root process in the system container
func cfgCapabilities(spec *specs.Spec) {

	// In a system container, root has all capabilities within the container's user
	// namespace; but note that the kernel will only allow privileged access to namespaced
	// resources and restrict access to non-namespaced resources.
	caps := spec.Process.Capabilities
	setAllCaps(&caps.Bounding)
	setAllCaps(&caps.Effective)
	setAllCaps(&caps.Inheritable)
	setAllCaps(&caps.Permitted)
	setAllCaps(&caps.Ambient)
}

// setAllCaps sets all capabilities in the given capability set
func setAllCaps(capSet *[]string) {
	*capSet = []string{
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
}

// cfgMaskedPaths removes from the container's config any masked paths for which
// sysvisor-fs will handle accesses.
func cfgMaskedPaths(spec *specs.Spec) {
	paths := spec.Linux.MaskedPaths
	for i := 0; i < len(paths); i++ {
		for _, mount := range sysvisorfsMounts {
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
// sysvisor-fs will handle accesses.
func cfgReadonlyPaths(spec *specs.Spec) {
	paths := spec.Linux.ReadonlyPaths
	for i := 0; i < len(paths); i++ {
		for _, mount := range sysvisorfsMounts {
			if paths[i] == mount.Destination {
				paths = append(paths[:i], paths[i+1:]...)
				i--
				break
			}
		}
	}
	spec.Linux.ReadonlyPaths = paths
}

// cfgSysvisorfsMounts adds the sysvisor-fs mounts to the containers config.
func cfgSysvisorfsMounts(spec *specs.Spec) {

	// remove from the config any mounts that conflict with sysvisorfs mounts
	for i := 0; i < len(spec.Mounts); i++ {
		for _, mount := range sysvisorfsMounts {
			if spec.Mounts[i].Destination == mount.Destination {
				spec.Mounts = append(spec.Mounts[:i], spec.Mounts[i+1:]...)
				i--
				break
			}
		}
	}

	// add sysvisorfs mounts to the config
	for _, mount := range sysvisorfsMounts {
		spec.Mounts = append(spec.Mounts, mount)
	}
}

// cfgCgroupPath configures the system container's cgroupPath.
func cfgCgroupPath(spec *specs.Spec) (error) {

	// System container specs require a cgroupsPath that contains the
	// cgroup resources assigned to the system container.
	if spec.Linux.CgroupsPath == "" {
		return fmt.Errorf("cgroupsPath not found in spec")
	}

	// Remove the read-only attribute from the cgroup mount
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

	// Add a new sub-dir to the cgroupsPath; this sub-dir will be chowned to the sys
	// container's root process and bind-mounted read-write to the system container's
	// cgroupfs (i.e., /sys/fs/cgroup) when the sys container is initialized. This way, a
	// root process in the system container can create sub cgroups, while unable to modify
	// the cgroup resources assigned to the system container itself.
	// spec.Linux.CgroupsPath = filepath.Join(spec.Linux.CgroupsPath, "syscont")

	return nil
}

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(spec *specs.Spec, strict bool) (error) {

	// TODO: Modify the spec for sys containers here;
	// validate and return the modified spec. Also, modify the seccomp
	// config for sys containers. Log messages when performing conversions.
	// If comparison should be strict, report errors on incompatible configs.

	cfgNamespaces(spec)
	cfgUidMappings(spec)
	cfgGidMappings(spec)
	cfgCapabilities(spec)
	cfgMaskedPaths(spec)
	cfgReadonlyPaths(spec)
	cfgSysvisorfsMounts(spec)

	err := cfgCgroupPath(spec)
	if err != nil {
		return fmt.Errorf("failed to configure cgroup mounts: %v", err)
	}

	// Remove readonly root filesystem config (spec.Root.Readonly)

	// Remove prestart hooks

	// cfg process spec
	// - uid/gid must be 0
	// - entry point must be system daemon

	// cfg seccomp config

	return nil
}
