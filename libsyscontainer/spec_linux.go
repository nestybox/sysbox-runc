// +build linux

package libsyscontainer

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

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

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(spec *specs.Spec, strict bool) (err error) {

	// TODO: Modify the spec for sys containers here;
	// validate and return the modified spec. Also, modify the seccomp
	// config for sys containers. Log messages when performing conversions.
	// If comparison should be strict, report errors on incompatible configs.

	cfgNamespaces(spec)
	cfgUidMappings(spec)
	cfgGidMappings(spec)
	cfgCapabilities(spec)

	// cfg cgroups path & mount (should be rw)

	// remove prestart hooks

	// cfg masked paths

	// cfg read-only paths

	// cfg mounts

	// cfg process spec
	// - uid/gid must be 0
	// - entry point must be system daemon

	// cfg seccomp config

	return nil
}
